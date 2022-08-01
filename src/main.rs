use askama::Template;
use async_std::task;
use std::str;
use tide::Request;

use clap::Parser;
use serde_derive::{Deserialize, Serialize};

use argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};

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

#[derive(Deserialize, Serialize, Debug)]
struct Query {
    /// dir name where to store the data
    d: String,
    /// size limit in bytes
    s: u64,
}

#[derive(Clone)]
struct State {
    key: Vec<u8>,
    base_url: String,
}

impl State {
    fn new(secret: String, base_url: String) -> Self {
        let pwd = secret.into_bytes();
        let salt = b"fixedsaltforargon";
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            hash_length: 32,
            ..Default::default()
        };
        let key = argon2::hash_raw(&pwd, salt, &config).unwrap();
        State { key, base_url }
    }

    fn decrypt(&self, s: &str) -> Result<Query, String> {
        let bytes = base64::decode_config(s, base64::URL_SAFE).map_err(|err| err.to_string())?;
        let nonce = Nonce::from_slice(&bytes[..12]);
        let ciphertext: &[u8] = &bytes[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|err| err.to_string())?;
        let plaintext = str::from_utf8(&plaintext).map_err(|err| err.to_string())?;
        serde_urlencoded::from_str(plaintext).map_err(|err| err.to_string())
    }

    fn encrypt(&self, q: Query) -> String {
        let plain = serde_urlencoded::to_string(q).unwrap();
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher.encrypt(nonce, plain.as_ref()).unwrap();
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);
        base64::encode_config(result, base64::URL_SAFE)
    }
}

#[test]
fn enc_dec() {
    let s = State::new("secret".to_owned(), "baseURL".to_owned());

    let q = Query {
        d: "test".to_owned(),
        s: 501,
    };
    let q = s.decrypt(&s.encrypt(q)).expect("decryption must work");
    assert_eq!(q.d, "test");
    assert_eq!(q.s, 501);
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {}

#[derive(Template)]
#[template(path = "upload_help.html.j2")]
struct UploadHelpTemplate<'a> {
    maxsize: u64,
	url: &'a str,
}

#[derive(Template)]
#[template(path = "gen.html.j2")]
struct GenTemplate {}

#[derive(Template)]
#[template(path = "gen_res.html.j2")]
struct GenResTemplate<'a> {
    link: &'a str,
}

async fn async_main(args: Args) -> tide::Result<()> {
    tide::log::start();

    let port = args.port;
    let mut app = tide::with_state(State::new(args.secret, args.base_url));
    app.at("/").get(index);
    app.at("/gen").get(get_gen).post(post_gen);
    app.at("/:token/").put(upload).get(upload_help);
    app.at("/:token/:name").put(upload).get(upload_help);
    app.listen(("127.0.0.1", port)).await?;
    Ok(())
}

async fn get_gen(mut _req: Request<State>) -> tide::Result {
    Ok(GenTemplate {}.into())
}

#[derive(Deserialize, Debug)]
struct GenQuery {
    /// dir name where to store the data
    n: String,
    // secret
    s: String,
    /// size limit in bytes
    m: u64,
}

async fn post_gen(mut req: Request<State>) -> tide::Result {
    let body: GenQuery = req.body_form().await?;
    let state = State::new(body.s, "".to_owned());

    let data = state.encrypt(Query {
        d: body.n,
        s: body.m,
    });

    Ok(GenResTemplate {
        link: &format!("{}/{data}/", req.state().base_url),
    }
    .into())
}

async fn index(mut _req: Request<State>) -> tide::Result {
    Ok(IndexTemplate {}.into())
}

use async_std::fs::{DirBuilder, OpenOptions};
use async_std::io::copy;

async fn upload(req: Request<State>) -> tide::Result {
    let token = req.param("token")?;
    let temp_name = u64::to_string(&OsRng.next_u64());
    let name = req.param("name").unwrap_or_else(|_| &temp_name);
    let query = req
        .state()
        .decrypt(token)
        .map_err(|err| tide::Error::from_str(500, err))?;

    let fs_path = format!("{}/{}", query.d, name);

    DirBuilder::new().recursive(true).create(query.d).await?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&fs_path)
        .await?;

    let bytes_written = copy(req, file).await?;

    /*info!("file written", {
        bytes: bytes_written,
        path: fs_path.canonicalize()?.to_str()
    });*/

    Ok(format!("{} bytes uploaded\n", bytes_written).into())
}

async fn upload_help(req: Request<State>) -> tide::Result {
    let token = req.param("token")?;
    let query = req.state().decrypt(token);

	let url = format!("{}/{token}/", req.state().base_url);
    match query {
        Ok(query) => Ok(UploadHelpTemplate { maxsize: query.s, url: &url }.into()),
        Err(err) => Err(tide::Error::from_str(400, err)),
    }
}

fn main() -> tide::Result<()> {
    let args = Args::parse();
    task::block_on(async_main(args))
}
