use async_std::fs;
use async_std::fs::DirBuilder;
use async_std::fs::File;
use async_std::fs::OpenOptions;
use async_std::fs::ReadDir;
use async_std::path::Path;
use async_std::stream::StreamExt;
use serde_derive::{Deserialize, Serialize};

use std::os::unix::prelude::MetadataExt;
use std::str;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use log::warn;

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Token {
    /// dir name where to store the data
    d: String,
    /// size limit in bytes
    s: u64,
    /// timeout (unix timestamp)
    t: u64,
}

impl Token {
    pub async fn file_names(&self) -> ReadDir {
        let path = Path::new(&self.d);
        if !(path.exists().await && path.is_dir().await) {
            self.create_referenced_directory().await;
        }

        fs::read_dir(path).await.unwrap()
    }

    async fn existing_data_size(&self) -> u64 {
        let mut size = 0u64;
        let mut filenames = self.file_names().await;
        while let Some(res) = filenames.next().await {
            if let Ok(dir) = res {
                size += dir.metadata().await.unwrap().size()
            }
        }

        size
    }

    pub async fn size_limit(&self) -> u64 {
        self.s - self.existing_data_size().await
    }

    pub fn new(dir_name: String, maxsize: u64, validity_duration: u64) -> Self {
        Token {
            d: dir_name,
            s: maxsize,
            t: current_unix_timestamp() + validity_duration,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.d.contains('/') {
            return Err("the given path contains invalid characters");
        }

        Ok(())
    }

    pub fn from_str(source: &str) -> Result<Self, impl std::error::Error> {
        serde_urlencoded::from_str(source)
    }
    pub fn is_expired(&self) -> bool {
        self.t < current_unix_timestamp()
    }

    /// Works properly only when not expired
    pub fn remaining_time_secs(&self) -> u64 {
        assert!(!self.is_expired());
        self.t - current_unix_timestamp()
    }

    async fn create_referenced_directory(&self) {
        DirBuilder::new()
            .recursive(true)
            .create(&self.d)
            .await
            .expect("creating directory should never fail");
    }

    pub async fn create_file_writer(&self, name: &str) -> Result<File, String> {
        self.create_referenced_directory().await;

        /* check for finished file name collision */
        let final_name = self.get_final_file_name(name);
        let final_path = Path::new(&final_name);
        if final_path.exists().await {
            return Err("file already exists".to_owned());
        }

        /* create partial file writer */
        let result = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.get_partial_file_name(name))
            .await
            .map_err(|err| {
                if err.raw_os_error().unwrap_or(0) == 17 {
                    "file already exists".to_owned()
                } else {
                    format!("error: {err}")
                }
            });

        /* we could have had a race condition here and someone could have uploaded a full file between
        the two checks --> there could be both the partial and normal file in the filesystem at this moment */
        if result.is_ok() && final_path.exists().await {
            /* if both files exist, remove the newly created partial file as it's useless
            note: the file is still opened when deleted, but that does not matter on Linux */
            let r = async_std::fs::remove_file(self.get_partial_file_name(name)).await;
            if let Err(e) = r {
                warn!("failed to delete partial file after a race condition, manual cleanup necessary: {e}");
            }
            Err("file already exists".to_owned())
        } else {
            result
        }
    }

    fn get_partial_file_name(&self, name: &str) -> String {
        // the idea is, that `name` cannot contain the $ character (it will be URL escaped)
        format!("{}/{name}$.partial", self.d)
    }

    fn get_final_file_name(&self, name: &str) -> String {
        format!("{}/{name}", self.d)
    }

    pub async fn mark_upload_final(&self, name: &str) -> std::io::Result<()> {
        async_std::fs::rename(
            self.get_partial_file_name(name),
            self.get_final_file_name(name),
        )
        .await
    }
}

impl ToString for Token {
    fn to_string(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl From<Token> for String {
    fn from(t: Token) -> Self {
        t.to_string()
    }
}
