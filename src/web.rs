use crate::crypto::CryptoState;
use crate::data::{DirectoryRegistry, UploadCapability};
use crate::templates::{IndexTemplate, UploadHelpTemplate, UploadResponseTemplate};
use crate::Args;
use async_std::io::copy;
use log::warn;
use rand_core::{OsRng, RngCore};
use std::error::Error;
use std::str;
use tide::{utils::After, Request};

use serde_derive::Deserialize;

#[derive(Clone)]
struct Context {
    crypto: CryptoState,
    dirs: DirectoryRegistry,
    base_url: String,
    public_dir: Option<String>,
}

impl Context {
    fn new(secret: &str, base_url: String, public_dir: Option<String>) -> Self {
        Context {
            crypto: CryptoState::new(secret),
            base_url,
            public_dir,
            dirs: DirectoryRegistry::new(),
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

    fn create_public_capability(&self) -> UploadCapability {
        let token = UploadCapability::new(
            self.public_dir
                .as_ref()
                .expect("can't create public token when there is no public dir set")
                .clone(),
            u64::MAX,
            u64::MAX / 2,
        );

        /* run validation */
        token.validate().expect("public token validation failed");

        token
    }
}

pub async fn start_webserver(args: Args) -> tide::Result<()> {
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
    app.listen((args.listen_ip, port)).await?;
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

fn token_to_link(ctx: &Context, tok: &UploadCapability) -> String {
    ctx.create_link(&ctx.crypto.encrypt(&tok.to_string()))
}

async fn post_gen(mut req: Request<Context>) -> tide::Result {
    let body: GenQuery = req.body_form().await?;
    let token = UploadCapability::new(body.n, body.m, body.t);
    let link = token_to_link(req.state(), &token);

    let crypt = CryptoState::new(&body.s);
    let valid_secret = crypt == req.state().crypto;

    if valid_secret {
        Ok(tide::Redirect::new(link).into())
    } else {
        Ok(IndexTemplate::new(true).into())
    }
}

async fn index(_req: Request<Context>) -> tide::Result {
    Ok(IndexTemplate::new(false).into())
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
    let tok = UploadCapability::from_str(&tok).unwrap();

    handle_upload(tok, name, body, content_length, req.state()).await
}

async fn handle_upload(
    cap: UploadCapability,
    name: &str,
    body: tide::Body,
    content_length: Option<u64>,
    ctx: &Context,
) -> tide::Result {
    if cap.is_expired() {
        return Err(tide::Error::from_str(403, "link expired\n"));
    }
    if let Err(err) = cap.validate() {
        return Err(tide::Error::from_str(
            400,
            format!("link data invalid: {err}\n"),
        ));
    }

    /* get a target directory reference */
    let directory = ctx.dirs.get(cap.dir_name()).await?;

    if body.len().unwrap_or(0) as u64 > directory.get_remaining_bytes(&cap) {
        return Err(tide::Error::from_str(
            400,
            "the data want to upload does not fit within the data limit\n",
        ));
    }
    if directory.get_remaining_bytes(&cap) == 0 {
        return Err(tide::Error::from_str(
            400,
            "no more data is allowed to be uploaded, limit exceeded\n",
        ));
    }

    let mut file = match directory
        .create_file_writer(&cap, name, content_length)
        .await
    {
        Ok(a) => a,
        Err(err) => {
            warn!("Error processing request: {}", err);
            return Err(tide::Error::from_str(500, err));
        }
    };

    let mut msgs = vec![];

    /* process the uploaded data */
    let res = copy(body, &mut file).await; // we ignore errors, they are handled by the custom writer itself
    if let Err(e) = res {
        warn!("IO error: {:?}", e);
        if let Some(err) = e.source() {
            msgs.push(format!("IO error while transfering the file: {}", err));
        } else {
            msgs.push("IO error while transferring the file: unknown".to_owned());
        }
    }
    let bytes_written = file.get_bytes_really_written();

    // the file writer object handles renames, deallocation of IO objects and everything else
    let m = file.finalize().await;
    msgs.extend(m);

    /* return message that will be displayed to curl users */
    Ok(UploadResponseTemplate::new(bytes_written, msgs).into())
}

async fn upload_public(mut req: Request<Context>) -> tide::Result {
    let body = req.take_body();
    let content_length = req
        .header("Content-Length")
        .map(|h| h.as_str().parse::<u64>().ok())
        .unwrap_or(None);
    let temp_name = u64::to_string(&OsRng.next_u64());
    let name = req.param("name").unwrap_or(&temp_name);
    let cap = req.state().create_public_capability();

    handle_upload(cap, name, body, content_length, req.state()).await
}

async fn upload_help(req: Request<Context>) -> tide::Result {
    let token = req.param("token")?;
    let query = req
        .state()
        .crypto
        .decrypt(token)
        .map_err(|err| tide::Error::from_str(400, err))?;
    let cap = UploadCapability::from_str(&query);

    let url = req.state().create_link(token);
    match cap {
        Ok(cap) => Ok(UploadHelpTemplate::from(
            url.as_str(),
            &cap,
            req.state().dirs.get(cap.dir_name()).await?,
        )
        .await
        .into()),
        Err(err) => Err(tide::Error::from_str(400, err)),
    }
}

async fn upload_help_public(req: Request<Context>) -> tide::Result {
    let url = req.state().create_public_link();
    let cap = req.state().create_public_capability();
    Ok(UploadHelpTemplate::from(
        url.as_str(),
        &cap,
        req.state().dirs.get(cap.dir_name()).await?,
    )
    .await
    .into())
}
