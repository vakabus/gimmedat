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
    // secret
    secret: String,
}

pub async fn post_auth(
    State(ctx): State<Box<Context>>,
    Form(body): Form<GenQuery>,
) -> impl IntoResponse {
    if ctx.crypto.is_secret_correct(&body.secret) {
        let token = Capability::root();
        let link = ctx.create_relative_link(&token);
        Redirect::to(&link).into_response()
    } else {
        IndexTemplate::new(true).into_response()
    }
}

pub async fn get_index(State(ctx): State<Box<Context>>) -> impl IntoResponse {
    if ctx.is_open_access_enabled() {
        Redirect::to(&ctx.create_relative_link(&Capability::root())).into_response()
    } else {
        IndexTemplate::new(false).into_response()
    }
}

pub async fn get_upload_help(
    State(ctx): State<Box<Context>>,
    Path(capability): Path<String>,
    OptionalPath(_name): OptionalPath<String>,
) -> axum::response::Result<impl IntoResponse> {
    let cap = ctx.parse_capability(capability)?;

    Ok(Html(
        UploadHelpTemplate::from(
            &ctx.create_absolute_link(&cap),
            &cap,
            ctx.get_directory_ref(&cap).await?,
        )
        .await
        .to_string(),
    ))
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

        // add subcapabilities only if reading is disabled
        let link = if cap.can_read() {
            Some(ctx.create_relative_link(&cap.child(&entry.file_name())))
        } else {
            None
        };

        files.push(crate::templates::File::new(
            metadata.is_file(),
            entry.file_name().to_string_lossy().into(),
            link
        ));
    }
    files.sort();
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

    Ok(Box::new(BrowseTemplate::new(cap, files)).into_response())
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
