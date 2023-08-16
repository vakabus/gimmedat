use std::borrow::Cow;
use std::os::unix::prelude::OsStrExt;

use async_std::fs::{read_dir, DirEntry};
use axum::body::StreamBody;
use axum::extract::{Path, State};
use axum::headers::{ContentDisposition, ContentLength, ContentType, Header, HeaderMapExt};
use axum::http::{response::Response, StatusCode};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{ErrorResponse, Html, IntoResponse, Redirect, Result};
use axum::{Form, TypedHeader};
use axum_extra::extract::OptionalPath;
use bytes::Bytes;
use format_bytes::format_bytes;
use futures_lite::StreamExt;
use serde_derive::Deserialize;
use tracing::log::warn;
use urlencoding::encode;

use crate::data::Capability;
use crate::templates::{BrowseTemplate, IndexTemplate, UploadHelpTemplate, ErrorTemplate};

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
    let token = Capability::new(body.n, body.m, body.t);
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
    let cap = ctx.parse_capability(capability)?;

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

async fn prep_file_list(
    path: &async_std::path::Path,
    ctx: &Box<Context>,
    cap: &Capability,
) -> Vec<crate::templates::File> {
    let entries: Vec<DirEntry> = read_dir(path)
        .await
        .unwrap()
        .collect::<Vec<std::io::Result<DirEntry>>>()
        .await
        .into_iter()
        .map(|v| v.unwrap())
        .collect();
    let mut files = vec![];
    for entry in entries {
        let metadata = entry.metadata().await.unwrap();
        let link = Some(ctx.create_relative_link(&cap.child(&entry.file_name())));
        if metadata.is_dir() {
            files.push(crate::templates::File::new(
                format!(
                    "{}/",
                    <Cow<'_, str> as Into<String>>::into(entry.file_name().to_string_lossy())
                ),
                link,
            ));
        } else {
            files.push(crate::templates::File::new(
                entry.file_name().to_string_lossy().into(),
                link,
            ));
        };
    }
    files
}

pub async fn get_browse(
    State(ctx): State<Box<Context>>,
    Path(token): Path<String>,
) -> axum::response::Result<impl IntoResponse> {
    /* check request validity */
    let cap = ctx.parse_capability(token)?;

    if cap.is_expired() {
        // FIXME the capability should not be possible to construct if it is invalid
        return Ok((StatusCode::FORBIDDEN, ErrorTemplate::new("Unfortunately, the link expired!".to_owned())).into_response());
    }

    /* get reffered file type */
    let path = cap.path();
    let metadata = path
        .metadata()
        .await
        .expect("the file probably does not exists");

    /* handle request depending on the referred file type */
    if metadata.is_dir() {
        get_browse_dir(cap, ctx).await.map(|o| o.into_response())
    } else {
        get_browse_file(cap, ctx).await.map(|o| o.into_response())
    }
}

async fn get_browse_dir(
    cap: Capability,
    ctx: Box<Context>,
) -> Result<impl IntoResponse, ErrorResponse> {
    /* list files */
    let files = if cap.can_list() {
        Some(prep_file_list(cap.path(), &ctx, &cap).await)
    } else {
        None
    };

    Ok(Box::new(BrowseTemplate::new(files)).into_response())
}

async fn get_browse_file(cap: Capability, _ctx: Box<Context>) -> Result<impl IntoResponse> {
    if !cap.can_read() {
        return Err(ErrorResponse::from(
            "you are not allowed to read the linked file",
        ));
    }

    let path = cap.path();
    let file = tokio::fs::File::open(path).await.map_err(|e| {
        warn!("failed to open a file: {:?}", e);
        ErrorResponse::from((
            StatusCode::INTERNAL_SERVER_ERROR,
            "error reading the referred file",
        ))
    })?;
    let len = file.metadata().await.unwrap().len();
    let stream = tokio_util::io::ReaderStream::new(file);

    /* headers (file name, content length, content type) */
    let mut headers = HeaderMap::new();
    let filename = cap.path().file_name().unwrap().to_string_lossy();
    let filename = encode(&filename);
    let bytes = Bytes::from(format!("attachment; filename*=UTF-8''\"{}\"", filename));
    headers.insert(
        "Content-Disposition",
        HeaderValue::from_maybe_shared(bytes).expect("encoded string should never be a problem"),
    );
    headers.typed_insert(ContentType::octet_stream());
    headers.typed_insert(ContentLength(len));

    /* response */
    Ok((headers, StreamBody::new(stream)).into_response())
}
