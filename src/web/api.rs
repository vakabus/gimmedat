use async_std::{io::WriteExt, stream::StreamExt};
use axum::{
    extract::{BodyStream, Path, Query, State},
    headers::ContentLength,
    http::StatusCode,
    response::{ErrorResponse, IntoResponse, Redirect},
    TypedHeader,
};
use axum_extra::extract::OptionalPath;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer};
use tracing::{info, warn};

use crate::{data::Capability, templates::UploadResponseTemplate};

use super::Context;

#[axum::debug_handler]
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

    /* get a target directory reference */
    let directory = ctx.get_directory_ref(&cap).await?;

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
            warn!("creating file writer failed: {}", err);
            return Err(ErrorResponse::from((
                StatusCode::BAD_REQUEST,
                err.to_string(),
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
    if !ctx.is_open_access_enabled() {
        return Err(ErrorResponse::from((
            StatusCode::FORBIDDEN,
            "Open access is not enabled!".to_owned(),
        )));
    }

    let content_length = content_length.map(|c| c.0 .0);
    let name = name.unwrap_or_else(|| OsRng.next_u64().to_string());
    let cap = Capability::root();

    Ok(handle_upload(cap, name, body, content_length, ctx).await)
}

const fn u64_max() -> u64 {
    u64::MAX
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapUpdateQuery {
    #[serde(default)]
    block_read: bool,
    #[serde(default)]
    block_write: bool,
    #[serde(default)]
    block_list: bool,
    #[serde(default)]
    block_capability_changes: bool,

    #[serde(default = "u64_max", deserialize_with = "from_suffixed_str_time")]
    remaining_seconds: u64,
    #[serde(default = "u64_max", deserialize_with = "from_suffixed_str_size")]
    remaining_bytes: u64,
}

fn from_suffixed_str_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    from_suffixed_str(
        deserializer,
        ['k', 'm', 'g', 't', 'p'],
        [1 << 10, 1 << 20, 1 << 30, 1 << 40, 1 << 50],
    )
}

fn from_suffixed_str_time<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    from_suffixed_str(
        deserializer,
        ['s', 'm', 'h', 'd', 'w', 'y'],
        [
            1,
            60,
            60 * 60,
            60 * 60 * 24,
            60 * 60 * 24 * 7,
            60 * 60 * 24 * 365,
        ],
    )
}

fn from_suffixed_str<'de, D, const N: usize>(
    deserializer: D,
    suffixes: [char; N],
    multipliers: [u64; N],
) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let input = String::deserialize(deserializer)?;

    // to lowercase
    let input = input.to_lowercase();

    // default
    if input.is_empty() {
        return Ok(u64::MAX);
    }

    // no suffix
    if let Ok(res) = input.parse::<u64>() {
        return Ok(res);
    }

    // suffix
    if let Ok(res) = input[..input.len() - 1].parse::<u64>() {
        let suff = input.chars().last().unwrap();
        let pos = suffixes.iter().position(|c| *c == suff);
        if pos.is_none() {
            return Err(serde::de::Error::custom(format!(
                "invalid value suffix, only {:?} allowed",
                suffixes
            )));
        }
        return Ok(res * multipliers[pos.unwrap()]);
    }

    Err(serde::de::Error::custom(&format!("invalid suffixed number value, expected a number followed by a single character suffix out of {:?}", suffixes)))
}

pub async fn get_update_capability(
    State(ctx): State<Box<Context>>,
    Path(token): Path<String>,
    Query(qry): Query<CapUpdateQuery>,
) -> axum::response::Result<impl IntoResponse> {
    let mut cap = ctx.parse_capability(token)?;

    assert!(cap.can_be_modified());

    if qry.block_capability_changes {
        cap = cap.block_capability_modifications();
    }
    if qry.block_list {
        cap = cap.block_listing();
    }
    if qry.block_read {
        cap = cap.block_reading();
    }
    if qry.block_write {
        cap = cap.block_writing();
    }

    cap = cap
        .set_remaining_secs(qry.remaining_seconds)
        .set_size_limit(qry.remaining_bytes);

    // redirect at the end
    Ok(Redirect::to(&ctx.create_relative_link(&cap)))
}
