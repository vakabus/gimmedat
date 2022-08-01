use async_std::fs::DirBuilder;
use async_std::fs::File;
use async_std::fs::OpenOptions;
use serde_derive::{Deserialize, Serialize};

use std::str;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
    pub fn size_limit(&self) -> u64 {
        self.s
    }

    pub fn new(dir_name: String, maxsize: u64, validity_duration: u64) -> Self {
        Token {
            d: dir_name,
            s: maxsize,
            t: current_unix_timestamp() + validity_duration,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.d.contains("/") {
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
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(format!("{}/{name}", self.d))
            .await
            .map_err(|err| format!("error: {}", err.to_string()))
    }
}

impl ToString for Token {
    fn to_string(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl Into<String> for Token {
    fn into(self) -> String {
        self.to_string()
    }
}
