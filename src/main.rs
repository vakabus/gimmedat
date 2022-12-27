use askama::Template;
use async_std::{
    io::ReadExt,
    stream::{IntoStream, StreamExt},
    task,
};
use data::Token;
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
}

impl Context {
    fn new(secret: &str, base_url: String) -> Self {
        Context {
            crypto: CryptoState::new(secret),
            base_url,
        }
    }

    fn create_link(&self, token: &str) -> String {
        format!("{}/{}/", self.base_url, token)
    }
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {}

#[derive(Template)]
#[template(path = "upload_help.html.j2")]
struct UploadHelpTemplate<'a> {
    remaining_sec: u64,
    maxsize_bytes: u64,
    url: &'a str,
    uploaded_files: Vec<String>,
}

#[derive(Template)]
#[template(path = "gen_res.html.j2")]
struct GenResTemplate<'a> {
    valid_secret: bool,
    link: &'a str,
}

async fn async_main(args: Args) -> tide::Result<()> {
    tide::log::start();

    let port = args.port;
    let mut app = tide::with_state(Context::new(&args.secret, args.base_url));
    app.with(After(|mut res: tide::Response| async {
        if res.error().is_some() {
            let msg = match res.take_error() {
                Some(msg) => format!("{}", msg),
                None => String::from("unknown error"),
            };
            res.set_body(msg);
        }
        Ok(res)
    }));
    app.at("/").get(index);
    app.at("/gen").post(post_gen);
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

async fn post_gen(mut req: Request<Context>) -> tide::Result {
    let body: GenQuery = req.body_form().await?;
    let crypt = CryptoState::new(&body.s);
    let link = req
        .state()
        .create_link(&crypt.encrypt(&Token::new(body.n, body.m, body.t).to_string()));
    let valid_secret = crypt == req.state().crypto;

    Ok(GenResTemplate {
        link: &link,
        valid_secret,
    }
    .into())
}

async fn index(_req: Request<Context>) -> tide::Result {
    Ok(IndexTemplate {}.into())
}

async fn upload(req: Request<Context>) -> tide::Result {
    let token = req.param("token")?;
    let temp_name = u64::to_string(&OsRng.next_u64());
    let name = req.param("name").unwrap_or(&temp_name);
    let tok = req
        .state()
        .crypto
        .decrypt(token)
        .map_err(|err| tide::Error::from_str(401, err))?;
    let tok = Token::from_str(&tok).unwrap();

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
    if req.len().unwrap_or(0) as u64 > size_limit {
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
    let bytes_written = copy(req.take(size_limit), file).await?;

    /*info!("file written", {
        bytes: bytes_written,
        path: fs_path.canonicalize()?.to_str()
    });*/

    let additional_msg = if tok.size_limit().await == 0 {
        ", upload size limit exceeded (or reached exactly 0)"
    } else {
        ""
    };
    Ok(format!("{} bytes uploaded{}\n", bytes_written, additional_msg).into())
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
        Ok(query) => Ok(UploadHelpTemplate {
            remaining_sec: if query.is_expired() {
                0
            } else {
                query.remaining_time_secs()
            },
            maxsize_bytes: query.size_limit().await,
            url: &url,
            uploaded_files: query
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
        .into()),
        Err(err) => Err(tide::Error::from_str(400, err)),
    }
}

fn main() -> tide::Result<()> {
    let args = Args::parse();
    task::block_on(async_main(args))
}
