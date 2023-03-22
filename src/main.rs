use askama::Template;
use async_std::{
    io::ReadExt,
    stream::{IntoStream, StreamExt},
    task,
};
use data::Token;
use log::{info, warn};
use rand_core::{OsRng, RngCore};
use std::str;
use tide::{utils::After, Request};

use clap::Parser;
use serde_derive::Deserialize;

mod crypto;
mod data;

use async_std::io::copy;

use crate::crypto::CryptoState;

/// HTTP server used for accepting files from friends. Data
/// data are saved in the working directory
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Secret token used for cryptographically signing links
    #[clap(short, long)]
    secret: String,

    /// Allow unlimited uploads to a given directory on the root url
    #[clap(long)]
    public_access: Option<String>,

    /// TCP port to listen on
    #[clap(short, long, default_value_t = 3000)]
    port: u16,

    #[clap(short, long, default_value = "http://localhost:3000")]
    base_url: String,
}

#[derive(Clone)]
struct Context {
    crypto: CryptoState,
    base_url: String,
    public_dir: Option<String>,
}

impl Context {
    fn new(secret: &str, base_url: String, public_dir: Option<String>) -> Self {
        Context {
            crypto: CryptoState::new(secret),
            base_url,
            public_dir,
        }
    }

    fn create_link(&self, token: &str) -> String {
        format!("{}/{}/", self.base_url, token)
    }

    fn create_public_link(&self) -> String {
        format!("{}/", self.base_url)
    }

    fn public_access_enabled(&self) -> bool {
        self.public_dir.is_some()
    }

    fn create_public_token(&self) -> Token {
        let token = Token::new(
            self.public_dir
                .as_ref()
                .expect("can't create public token when there is no public dir set")
                .clone(),
            u64::MAX,
            u64::MAX / 2,
        );

        /* run validation */
        _ = token.validate().expect("public token validation failed");

        token
    }
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    invalid_secret: bool,
}

#[derive(Template)]
#[template(path = "upload.html.j2")]
struct UploadHelpTemplate<'a> {
    remaining_sec: u64,
    maxsize_bytes: u64,
    url: &'a str,
    uploaded_files: Vec<String>,
}

impl<'a> UploadHelpTemplate<'a> {
    async fn from(url: &'a str, token: Token) -> UploadHelpTemplate<'a> {
        Self {
            remaining_sec: if token.is_expired() {
                0
            } else {
                token.remaining_time_secs()
            },
            maxsize_bytes: token.size_limit().await,
            url,
            uploaded_files: token
                .file_names()
                .await
                .into_stream()
                .map(|r| {
                    r.map(|d| d.file_name().into_string().unwrap())
                        .unwrap_or_else(|_| "ERROR".to_owned())
                })
                .collect()
                .await,
        }
    }
}

#[derive(Template)]
#[template(path = "upload_response.txt.j2")]
struct UploadResponseTemplate {
    warn_content_length: bool,
    warn_size_limit_reached: bool,
    uploaded_bytes: u64,
}

impl UploadResponseTemplate {
    fn new(len: bool, size_limit: bool, bytes: u64) -> Self {
        Self {
            warn_content_length: len,
            warn_size_limit_reached: size_limit,
            uploaded_bytes: bytes,
        }
    }
}

async fn async_main(args: Args) -> tide::Result<()> {
    tide::log::start();

    let port = args.port;
    let mut app = tide::with_state(Context::new(
        &args.secret,
        args.base_url,
        args.public_access,
    ));
    app.with(After(|mut res: tide::Response| async {
        if res.error().is_some() {
            let msg = match res.take_error() {
                Some(msg) => format!("{msg}"),
                None => String::from("unknown error"),
            };
            res.set_body(msg);
        }
        Ok(res)
    }));
    if app.state().public_access_enabled() {
        app.at("/").get(upload_help_public);
        app.at("/:name").put(upload_public);
    } else {
        app.at("/").get(index);
        app.at("/gen").post(post_gen);
    }
    app.at("/:token/").put(upload).get(upload_help);
    app.at("/:token/:name").put(upload).get(upload_help);
    app.listen(("127.0.0.1", port)).await?;
    Ok(())
}

#[derive(Deserialize, Debug)]
struct GenQuery {
    /// dir name where to store the data
    n: String,
    // secret
    s: String,
    /// size limit in bytes
    m: u64,
    /// remaining time
    t: u64,
}

fn token_to_link(ctx: &Context, tok: &Token) -> String {
    ctx.create_link(&ctx.crypto.encrypt(&tok.to_string()))
}

async fn post_gen(mut req: Request<Context>) -> tide::Result {
    let body: GenQuery = req.body_form().await?;
    let token = Token::new(body.n, body.m, body.t);
    let link = token_to_link(&req.state(), &token);

    let crypt = CryptoState::new(&body.s);
    let valid_secret = crypt == req.state().crypto;

    if valid_secret {
        Ok(tide::Redirect::new(link).into())
    } else {
        Ok(IndexTemplate {
            invalid_secret: true,
        }
        .into())
    }
}

async fn index(_req: Request<Context>) -> tide::Result {
    Ok(IndexTemplate {
        invalid_secret: false,
    }
    .into())
}

async fn upload(mut req: Request<Context>) -> tide::Result {
    let body = req.take_body();
    let token = req.param("token")?;
    let content_length = req
        .header("Content-Length")
        .map(|h| h.as_str().parse::<u64>().ok())
        .unwrap_or(None);
    let temp_name = u64::to_string(&OsRng.next_u64());
    let name = req.param("name").unwrap_or(&temp_name);
    let tok = req
        .state()
        .crypto
        .decrypt(token)
        .map_err(|err| tide::Error::from_str(401, err))?;
    let tok = Token::from_str(&tok).unwrap();

    handle_upload(tok, name, body, content_length).await
}

async fn handle_upload(
    tok: Token,
    name: &str,
    body: tide::Body,
    content_length: Option<u64>,
) -> tide::Result {
    if tok.is_expired() {
        return Err(tide::Error::from_str(403, "link expired"));
    }
    if let Err(err) = tok.validate() {
        return Err(tide::Error::from_str(
            400,
            format!("link data invalid: {err}"),
        ));
    }

    let size_limit = tok.size_limit().await;
    if body.len().unwrap_or(0) as u64 > size_limit {
        return Err(tide::Error::from_str(400, "data size limit exceeded"));
    }
    if size_limit == 0 {
        return Err(tide::Error::from_str(
            400,
            "no more data is allowed to be uploaded, limit exceeded",
        ));
    }

    let file = tok
        .create_file_writer(name)
        .await
        .map_err(|err| tide::Error::from_str(403, err))?;

    /* the take() function makes sure the upload does not overshoot the upload limit,
    it can however result in truncated files 🤷*/
    let bytes_written = copy(body.take(size_limit), file).await.map_err(|err| {
        info!("wtf");
        tide::Error::from(err)
    })?;

    /* we won't be notified, if the stream ends in the middle, it will just end normally on our side,
    therefore, to check for completion, we use the Content-Length header */
    let warn_content_lenght_missing = if let Some(expected) = content_length {
        if expected == bytes_written {
            // great, everything as expected
            tok.mark_upload_final(name).await?;
        } else {
            warn!("upload of \"{name}\" not completed: expected={expected} real={bytes_written}");
        }
        false
    } else {
        warn!("upload of \"{name}\" did not contain Content-Length header, leaving it with partial name");
        true
    };

    /* return message that will be displayed to curl users */
    Ok(UploadResponseTemplate::new(
        warn_content_lenght_missing,
        tok.size_limit().await == 0,
        bytes_written,
    )
    .into())
}

async fn upload_public(mut req: Request<Context>) -> tide::Result {
    let body = req.take_body();
    let content_length = req
        .header("Content-Length")
        .map(|h| h.as_str().parse::<u64>().ok())
        .unwrap_or(None);
    let temp_name = u64::to_string(&OsRng.next_u64());
    let name = req.param("name").unwrap_or(&temp_name);
    let tok = req.state().create_public_token();

    handle_upload(tok, name, body, content_length).await
}

async fn upload_help(req: Request<Context>) -> tide::Result {
    let token = req.param("token")?;
    let query = req
        .state()
        .crypto
        .decrypt(token)
        .map_err(|err| tide::Error::from_str(400, err))?;
    let tok = Token::from_str(&query);

    let url = req.state().create_link(token);
    match tok {
        Ok(query) => Ok(UploadHelpTemplate::from(url.as_str(), query).await.into()),
        Err(err) => Err(tide::Error::from_str(400, err)),
    }
}

async fn upload_help_public(req: Request<Context>) -> tide::Result {
    let url = req.state().create_public_link();
    Ok(
        UploadHelpTemplate::from(url.as_str(), req.state().create_public_token())
            .await
            .into(),
    )
}

fn main() -> tide::Result<()> {
    let args = Args::parse();
    task::block_on(async_main(args))
}
