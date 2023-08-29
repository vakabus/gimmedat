use axum::response::{ErrorResponse, Result};
use nanoid::nanoid;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::CryptoState;
use crate::data::{Capability, Directory, DirectoryRegistry};
use crate::Args;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::routing::{get, post, put};
use axum::Router;
use http_body::combinators::UnsyncBoxBody;

use tower_http::trace::TraceLayer;
use tracing::{error, field, info, Span};

mod api;
mod ui;

#[derive(Clone)]
pub struct Context {
    crypto: CryptoState,
    dirs: DirectoryRegistry,
    base_url: String,
    /// whether we check for secret at /
    open: bool,
}

impl Context {
    fn new(secret: &str, base_url: String, public: bool) -> Self {
        Context {
            crypto: CryptoState::new(secret),
            base_url,
            open: public,
            dirs: DirectoryRegistry::new(),
        }
    }

    pub fn create_relative_update_url(&self, cap: &Capability) -> String {
        format!("/u/{}", self.crypto.encrypt(cap))
    }

    pub fn create_absolute_link(&self, cap: &Capability) -> String {
        format!("{}/c/{}/", self.base_url, &self.crypto.encrypt(cap))
    }

    pub fn create_relative_link(&self, cap: &Capability) -> String {
        format!("/c/{}/", &self.crypto.encrypt(cap))
    }

    fn is_open_access_enabled(&self) -> bool {
        self.open
    }

    pub fn parse_capability(&self, token: String) -> Result<Capability> {
        self.crypto
            .decrypt(token)
            .map_err(|_| ErrorResponse::from((StatusCode::BAD_REQUEST, "invalid capability")))
    }

    pub async fn get_directory_ref(
        &self,
        cap: &Capability,
    ) -> axum::response::Result<Arc<Directory>> {
        self.dirs
            .get(cap.path())
            .await
            .map_err(|e| ErrorResponse::from((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())))
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
                if response.status().is_server_error() {
                    error!(
                        status = display(response.status()),
                        duration = debug(latency),
                    );
                } else {
                    info!(
                        status = display(response.status()),
                        duration = debug(latency),
                    );
                };
            },
        );

    let app = Router::new()
        .route("/", get(ui::get_index))
        .route("/:name", put(api::put_upload_public))
        .route("/gen", post(ui::post_auth))
        .route("/c/:capability/", put(api::put_upload).get(ui::get_browse))
        .route("/c/:capability/:name", put(api::put_upload))
        .route("/u/:capability", get(api::get_update_capability))
        .layer(tracer);
    let app = app.with_state(Box::new(Context::new(
        &args.secret,
        args.base_url,
        args.public,
    )));

    /*
    if app.state().public_access_enabled() {
        app.at("/").get(upload_help_public);
        app.at("/:name").put(upload_public);
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
