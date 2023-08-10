use nanoid::nanoid;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::crypto::CryptoState;
use crate::data::{DirectoryRegistry, UploadCapability};
use crate::Args;
use axum::body::Body;
use axum::http::{Request, Response};
use axum::routing::{get, post, put};
use axum::Router;
use http_body::combinators::UnsyncBoxBody;

use tower_http::trace::TraceLayer;
use tracing::{field, info, warn, Span};

mod api;
mod ui;

#[derive(Clone)]
pub struct Context {
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
        format!("{}/{}/", self.base_url, &self.crypto.encrypt(cap))
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
        .route("/", get(ui::get_index))
        .route("/gen", post(ui::post_generate_link))
        .route(
            "/:capability/",
            put(api::put_upload).get(ui::get_upload_help),
        )
        .route(
            "/:capability/:name",
            put(api::put_upload).get(ui::get_upload_help),
        )
        .layer(tracer);
    let app = app.with_state(Box::new(Context::new(
        &args.secret,
        args.base_url,
        args.public_access,
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
