use std::sync::Arc;

use askama::Template;

use crate::data::{Capability, Directory};

#[derive(Template)]
#[template(path = "index.html.j2")]
pub struct IndexTemplate {
    invalid_secret: bool,
}

impl IndexTemplate {
    pub fn new(invalid_secret: bool) -> Self {
        Self { invalid_secret }
    }
}

#[derive(Template)]
#[template(path = "upload.html.j2")]
pub struct UploadHelpTemplate<'a> {
    remaining_sec: u64,
    maxsize_bytes: u64,
    url: &'a str,
    uploaded_files: Vec<String>,
}

impl<'a> UploadHelpTemplate<'a> {
    pub async fn from(
        url: &'a str,
        cap: &'a Capability,
        dir: Arc<Directory>,
    ) -> UploadHelpTemplate<'a> {
        Self {
            remaining_sec: if cap.is_expired() {
                0
            } else {
                cap.remaining_time_secs()
            },
            maxsize_bytes: dir.get_remaining_bytes(cap),
            url,
            uploaded_files: dir
                .list_files()
                .await
                .into_iter()
                .map(|r| {
                    r.into_string()
                        .unwrap_or("INVALID UTF8 FILENAME".to_owned())
                })
                .collect(),
        }
    }
}

#[derive(Template)]
#[template(path = "upload_response.txt.j2")]
pub struct UploadResponseTemplate {
    uploaded_bytes: u64,
    msgs: Vec<String>,
}

impl UploadResponseTemplate {
    pub fn new(bytes: u64, msgs: Vec<String>) -> Self {
        Self {
            uploaded_bytes: bytes,
            msgs,
        }
    }
}

pub struct File {
    name: String,
    link: Option<String>,
}

impl File {
    pub fn new(name: String, link: Option<String>) -> Self {
        Self { name, link }
    }
}

#[derive(Template)]
#[template(path = "browse.html.j2")]
pub struct BrowseTemplate {
    files: Option<Vec<File>>,
}

impl BrowseTemplate {
    pub fn new(files: Option<Vec<File>>) -> Self {
        Self { files }
    }
}

#[derive(Template)]
#[template(path = "error.html.j2")]
pub struct ErrorTemplate {
    error: String,
}

impl ErrorTemplate {
    pub fn new(error: String) -> Self {
        Self { error }
    }
}
