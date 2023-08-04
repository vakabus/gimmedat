use nanoid::nanoid;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing_subscriber::Layer;

use crate::crypto::CryptoState;
use crate::data::{DirectoryRegistry, UploadCapability};
use crate::templates::{IndexTemplate, UploadHelpTemplate, UploadResponseTemplate};
use crate::Args;
use async_std::io::WriteExt;
use async_std::stream::StreamExt;
use axum::body::Body;
use axum::extract::{BodyStream, Path, State};
use axum::headers::ContentLength;
use axum::http::{Request, Response, StatusCode};
use axum::response::{ErrorResponse, Html, IntoResponse, Redirect};
use axum::routing::{get, post, put};
use axum::{Form, Router, ServiceExt, TypedHeader};
use axum_extra::extract::OptionalPath;
use http_body::combinators::UnsyncBoxBody;
use rand_core::{OsRng, RngCore};

use serde_derive::Deserialize;
use tower_http::trace::TraceLayer;
use tracing::{event, field, info, warn, Level, Span};

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

    fn create_upload_link(&self, cap: &UploadCapability) -> String {
        format!("{}/{}/", self.base_url, &self.crypto.encrypt(&cap))
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

pub async fn start_webserver(args: Args) -> anyhow::Result<()> {
    let tracer = /* reconfigure tracing */
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request<Body>| {
            let span = tracing::info_span!("HTTP request", id = field::display(nanoid!(6)));
            span.in_scope(|| {
                info!(
                    method = display(request.method()),
                    path = display(request.uri().path()),
                );
            });
            span
        })
        .on_response(
            |response: &Response<UnsyncBoxBody<axum::body::Bytes, axum::Error>>,
             latency: Duration,
             _span: &Span| {
                if response.status().is_success() {
                    info!(
                        status = display(response.status()),
                        duration = debug(latency),
                    );
                } else {
                    warn!(
                        status = display(response.status()),
                        duration = debug(latency),
                    );
                };
            },
        );

    let app = Router::new()
        .route("/", get(get_index))
        .route("/gen", post(post_generate_link))
        .route("/:capability/", put(put_upload).get(get_upload_help))
        .route("/:capability/:name", put(put_upload).get(get_upload_help))
        .layer(tracer);
    let app = app.with_state(Box::new(Context::new(
        &args.secret,
        args.base_url,
        args.public_access,
    )));

    /*
    if app.state().public_access_enabled() {
        app.at("/").put(upload_public).get(upload_help_public);
        app.at("/:name").put(upload_public).get(upload_help_public);
    } else {
        app.at("/").get(index);
        app.at("/gen").post(post_gen);
    }
    app.at("/:token/").put(upload).get(upload_help);
    app.at("/:token/:name").put(upload).get(upload_help);
    */

    /* start the server */
    let addr: SocketAddr = (args.listen_ip.parse::<IpAddr>()?, args.port).into();
    info!("Server is listening on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    //app.listen((args.listen_ip, port)).await?;
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

async fn post_generate_link(
    State(ctx): State<Box<Context>>,
    Form(body): Form<GenQuery>,
) -> impl IntoResponse {
    let token = UploadCapability::new(body.n, body.m, body.t);
    let link = ctx.create_upload_link(&token);

    if ctx.crypto.is_secret_correct(&body.s) {
        Redirect::to(&link).into_response()
    } else {
        IndexTemplate::new(true).into_response()
    }
}

async fn get_index() -> impl IntoResponse {
    IndexTemplate::new(false)
}

async fn put_upload(
    State(ctx): State<Box<Context>>,
    Path((capability, name)): Path<(String, String)>,
    content_length: Option<TypedHeader<ContentLength>>,
    body: BodyStream,
) -> axum::response::Result<impl IntoResponse> {
    let content_length = content_length.map(|c| c.0 .0);
    let capability: UploadCapability = ctx.crypto.decrypt(capability)?;

    Ok(handle_upload(capability, name, body, content_length, ctx).await)
}

async fn handle_upload(
    cap: UploadCapability,
    name: String,
    mut body: BodyStream,
    content_length: Option<u64>,
    ctx: Box<Context>,
) -> axum::response::Result<impl IntoResponse> {
    if cap.is_expired() {
        return Err(ErrorResponse::from((
            StatusCode::UNAUTHORIZED,
            "link expired\n",
        )));
    }
    if let Err(err) = cap.validate() {
        return Err(ErrorResponse::from((
            StatusCode::BAD_REQUEST,
            format!("link data invalid: {err}\n"),
        )));
    }

    /* get a target directory reference */
    let directory = ctx
        .dirs
        .get(cap.dir_name())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    if content_length.unwrap_or(0) as u64 > directory.get_remaining_bytes(&cap) {
        return Err(ErrorResponse::from((
            StatusCode::PAYLOAD_TOO_LARGE,
            "the data want to upload does not fit within the data limit\n",
        )));
    }

    let mut file = match directory
        .create_file_writer(&cap, &name, content_length)
        .await
    {
        Ok(a) => a,
        Err(err) => {
            warn!("Error processing request: {}", err);
            return Err(ErrorResponse::from((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{err}"),
            )));
        }
    };

    let mut msgs = vec![];

    /* process the uploaded data */
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(bytes) => {
                if let Err(err) = file.write_all(&bytes).await {
                    warn!("upload failed due to write error: {err:?}");
                    msgs.push(format!("error while writing the file: {}", err));
                    break;
                }
            }
            Err(err) => {
                warn!("upload failed due to receive error: {err:?}");
                msgs.push(format!("error while receiving the file: {}", err));
                break;
            }
        }
    }

    // the file object handles everything, we just have to call finalize()
    let bytes_written = file.get_bytes_really_written();
    let m = file.finalize().await;
    msgs.extend(m);

    /* return message that will be displayed to curl users */
    info!("file '{}' uploaded (at least partially)", name);
    Ok(UploadResponseTemplate::new(bytes_written, msgs).into_response())
}

async fn put_upload_public(
    State(ctx): State<Box<Context>>,
    Path((capability, name)): Path<(String, Option<String>)>,
    content_length: Option<TypedHeader<ContentLength>>,
    body: BodyStream,
) -> axum::response::Result<impl IntoResponse> {
    let content_length = content_length.map(|c| c.0 .0);
    let name = name.unwrap_or_else(|| OsRng.next_u64().to_string());
    let cap = ctx.crypto.decrypt(capability)?;

    Ok(handle_upload(cap, name, body, content_length, ctx).await)
}

async fn get_upload_help(
    State(ctx): State<Box<Context>>,
    Path(capability): Path<String>,
    OptionalPath(_name): OptionalPath<String>,
) -> axum::response::Result<impl IntoResponse> {
    let cap = ctx.crypto.decrypt(capability)?;

    Ok(Html(
        UploadHelpTemplate::from(
            &ctx.create_upload_link(&cap),
            &cap,
            ctx.dirs
                .get(cap.dir_name())
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        )
        .await
        .to_string(),
    ))
}

async fn get_upload_help_public(
    State(ctx): State<Box<Context>>,
) -> axum::response::Result<impl IntoResponse> {
    let url = ctx.create_public_link();
    let cap = ctx.create_public_capability();
    Ok(UploadHelpTemplate::from(
        url.as_str(),
        &cap,
        ctx.dirs
            .get(cap.dir_name())
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    )
    .await
    .into_response())
}
