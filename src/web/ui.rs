use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::OptionalPath;
use serde_derive::Deserialize;

use crate::data::UploadCapability;
use crate::templates::{IndexTemplate, UploadHelpTemplate};

use super::Context;

#[derive(Deserialize, Debug)]
pub struct GenQuery {
    /// dir name where to store the data
    n: String,
    // secret
    s: String,
    /// size limit in bytes
    m: u64,
    /// remaining time
    t: u64,
}

pub async fn post_generate_link(
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

pub async fn get_index() -> impl IntoResponse {
    IndexTemplate::new(false)
}

pub async fn get_upload_help(
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

pub async fn get_upload_help_public(
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
