use askama::Template;

use crate::{
    data::{Capability, Directory},
    web::Context,
};

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

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct File {
    is_file: bool,
    name: String,
    link: String,
}

impl File {
    pub fn new(is_file: bool, name: String, link: String) -> Self {
        Self {
            is_file,
            name,
            link,
        }
    }
}

#[derive(Template)]
#[template(path = "browse.html.j2")]
pub struct BrowseTemplate {
    files: Option<Vec<File>>,
    current_bytes: u64,
    maxsize_bytes: u64,
    remaining_sec: u64,
    cap: Capability,
    url: String,
    update_url: String,
}

impl BrowseTemplate {
    pub fn new(
        cap: Capability,
        ctx: &Context,
        dir: &(dyn Directory + Send + Sync),
        files: Option<Vec<File>>,
    ) -> Self {
        Self {
            files,
            current_bytes: dir.get_total_bytes(),
            maxsize_bytes: cap.size_limit(),
            remaining_sec: cap.remaining_time_secs(),
            url: ctx.create_absolute_link(&cap),
            update_url: ctx.create_relative_update_url(&cap),
            cap,
        }
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
