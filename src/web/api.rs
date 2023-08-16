use async_std::{io::WriteExt, stream::StreamExt};
use axum::{
    extract::{BodyStream, Path, State},
    headers::ContentLength,
    http::StatusCode,
    response::{ErrorResponse, IntoResponse},
    TypedHeader,
};
use axum_extra::extract::OptionalPath;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};

use crate::{data::Capability, templates::UploadResponseTemplate};

use super::Context;

pub async fn put_upload(
    State(ctx): State<Box<Context>>,
    Path((token, name)): Path<(String, String)>,
    content_length: Option<TypedHeader<ContentLength>>,
    body: BodyStream,
) -> axum::response::Result<impl IntoResponse> {
    let content_length = content_length.map(|c| c.0 .0);
    let capability: Capability = ctx.parse_capability(token)?;

    Ok(handle_upload(capability, name, body, content_length, ctx).await)
}

async fn handle_upload(
    cap: Capability,
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

    if content_length.unwrap_or(0) > directory.get_remaining_bytes(&cap) {
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
                StatusCode::INTERNAL_SERVER_ERROR,  // FIXME this catches even legitimate errors with 500
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

pub async fn put_upload_public(
    State(ctx): State<Box<Context>>,
    OptionalPath(name): OptionalPath<String>,
    content_length: Option<TypedHeader<ContentLength>>,
    body: BodyStream,
) -> axum::response::Result<impl IntoResponse> {
    if ! ctx.is_open_access_enabled() {
        return Err(ErrorResponse::from((StatusCode::FORBIDDEN, "Open access is not enabled!".to_owned())));
    }

    let content_length = content_length.map(|c| c.0 .0);
    let name = name.unwrap_or_else(|| OsRng.next_u64().to_string());
    let cap = Capability::root();

    Ok(handle_upload(cap, name, body, content_length, ctx).await)
}
