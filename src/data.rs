use async_std::fs::File;
use async_std::fs::OpenOptions;
use async_std::sync::Mutex;
use log::error;
use log::warn;
use serde_derive::{Deserialize, Serialize};

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::read_dir;
use std::fs::DirBuilder;
use std::os::unix::prelude::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UploadCapability {
    /// dir name where to store the data
    d: String,
    /// size limit in bytes
    s: u64,
    /// timeout (unix timestamp)
    t: u64,
}

impl UploadCapability {
    pub fn size_limit(&self) -> u64 {
        self.s
    }

    pub fn new(dir_name: String, maxsize: u64, validity_duration: u64) -> Self {
        UploadCapability {
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

    pub fn expiration_time(&self) -> SystemTime {
        let dur = Duration::from_secs(self.t);
        UNIX_EPOCH + dur
    }

    /// Works properly only when not expired
    pub fn remaining_time_secs(&self) -> u64 {
        assert!(!self.is_expired());
        self.t - current_unix_timestamp()
    }

    pub fn dir_name(&self) -> &str {
        &self.d
    }
}

impl ToString for UploadCapability {
    fn to_string(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl From<UploadCapability> for String {
    fn from(t: UploadCapability) -> Self {
        t.to_string()
    }
}

pub struct Directory {
    path: PathBuf,
    real_size: AtomicU64,
    filenames: Mutex<HashSet<OsString>>,
}

impl Directory {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        Self::ensure_path_existence(&path);

        let size = AtomicU64::new(Self::calculate_existing_data_size(&path)?);
        let filenames = Mutex::new(Self::create_filename_set(&path)?);

        Ok(Self {
            path,
            real_size: size,
            filenames,
        })
    }

    fn ensure_path_existence(path: &Path) {
        if !(path.exists() && path.is_dir()) {
            DirBuilder::new()
                .recursive(true)
                .create(path)
                .expect("creating directory should never fail");
        }
    }

    fn assert_path_existence(path: &Path) {
        assert!(path.exists(), "Directory does not exist");
        assert!(path.is_dir(), "Path is not a directory");
    }

    fn create_filename_set(path: &Path) -> anyhow::Result<HashSet<OsString>> {
        Ok(read_dir(path)?.map(|e| e.unwrap().file_name()).collect())
    }

    fn calculate_existing_data_size(dir: &Path) -> anyhow::Result<u64> {
        let mut size = 0u64;
        for dir in read_dir(dir)?.flatten() {
            size += dir.metadata().unwrap().size(); // file content
            size += dir.file_name().len() as u64; // length of the file name
            size += 4096; // constant overhead to account for metadata space of empty files
        }

        Ok(size)
    }

    pub async fn create_file_writer<'a>(
        &'a self,
        uc: &UploadCapability,
        filename: &'a str,
        expected_size: Option<u64>,
    ) -> Result<DirectoryFileWriter<'a>, String> {
        Self::assert_path_existence(&self.path);
        let partial_name = self.get_partial_file_name(filename);

        let filename_os = OsString::from(filename);

        /* lock the filename we are working on */
        {
            /* check for finished file name collision & claim it if it's free */
            let mut names = self.filenames.lock().await;
            if names.contains(&filename_os) {
                return Err("file already exists".to_owned());
            }
            names.insert(filename_os);
        }

        /* there is still a possibility that a partial file exists, however we can
        be certain that we are not writing into it at the moment, so lets just ignore it
        and rewrite it */

        /* create partial file writer */
        let file = OpenOptions::new()
            .create(true) // this allows rewrites
            .truncate(true)
            .write(true)
            .open(partial_name)
            .await
            .expect("creating a new file should never fail here");

        /* report file constant bytes (same as in calculate_existing_data_size()) */
        self.report_bytes_written(4096);
        self.report_bytes_written(filename.len());

        /* create file writer object */
        Ok(DirectoryFileWriter::new(
            self,
            &self.real_size,
            file,
            uc.size_limit(),
            filename,
            expected_size,
            uc.expiration_time(),
        ))
    }

    fn report_bytes_written(&self, bytes: usize) {
        self.real_size.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn get_total_bytes(&self) -> u64 {
        self.real_size.load(Ordering::Relaxed)
    }

    pub fn get_remaining_bytes(&self, uc: &UploadCapability) -> u64 {
        u64::saturating_sub(uc.size_limit(), self.get_total_bytes())
    }

    fn get_partial_file_name(&self, name: &str) -> PathBuf {
        let name = format!("{name}$.partial");
        Path::join(&self.path, name)
    }

    fn get_final_file_name(&self, name: &str) -> PathBuf {
        Path::join(&self.path, name)
    }

    async fn mark_upload_final(&self, name: &str) -> std::io::Result<()> {
        async_std::fs::rename(
            self.get_partial_file_name(name),
            self.get_final_file_name(name),
        )
        .await
    }

    pub async fn list_files(&self) -> Vec<OsString> {
        let names = self.filenames.lock().await;
        names.clone().into_iter().collect()
    }
}

pub struct DirectoryFileWriter<'a> {
    dir: &'a Directory,
    filename: &'a str,
    file: File,

    /* internal state variables */
    errored: bool,
    finalized: bool,

    /* helper values for enforcing the size limit */
    total_size: &'a AtomicU64,
    expected_size: Option<u64>,
    bytes_written: u64,

    /* limits */
    max_dir_size: u64,
    expiration_time: SystemTime,
}

impl<'a> DirectoryFileWriter<'a> {
    pub fn new(
        dir: &'a Directory,
        total_size: &'a AtomicU64,
        file: File,
        max_dir_size: u64,
        filename: &'a str,
        expected_size: Option<u64>,
        expiration_time: SystemTime,
    ) -> Self {
        Self {
            dir,
            total_size,
            file,
            max_dir_size,
            errored: false,
            filename,
            expected_size,
            finalized: false,
            bytes_written: 0,
            expiration_time,
        }
    }

    pub fn get_bytes_really_written(&self) -> u64 {
        self.bytes_written
    }

    pub async fn finalize(mut self) -> Vec<String> {
        self.finalized = true;
        let mut msgs = vec![];

        /* we won't be notified, if the stream ends in the middle, it will just end normally on our side,
        therefore, to check for completion, we use the Content-Length header */
        if let Some(expected) = self.expected_size {
            if expected != self.bytes_written {
                warn!(
                    "upload of \"{}\" not completed: expected={expected} real={}",
                    self.filename, self.bytes_written
                );
                msgs.push(format!("upload not completed, we expected {expected} bytes due to the Content-Length header, but received only {}", self.bytes_written));
                self.errored = true; // we consider this state an error and will prevent renaming
            }
        } else {
            warn!("upload of \"{}\" did not contain Content-Length header, leaving it with partial name", self.filename);
            msgs.push("your request did not contain the Content-Length header, leaving it with partial name".to_owned());
            self.errored = true;
        };

        /* warn about data limit exhaustion */
        if u64::saturating_sub(self.max_dir_size, self.total_size.load(Ordering::Relaxed)) == 0 {
            msgs.push("data limit reached while uploading".to_owned());
        }

        if !self.errored {
            /* if no errors occured, lets rename the file to its final non-partial name */
            if let Err(e) = self.dir.mark_upload_final(self.filename).await {
                error!("Error renaming file after an upload: {e}");
                msgs.push("error renaming file after a complete upload, you can retry by uploading it again".to_owned());
            }
        } else {
            /* by removing the file from the hash set, we allow its reuploads */
            let mut lock = self.dir.filenames.lock().await;
            let name = OsString::from(self.filename);
            _ = lock.remove(&name);
        }

        msgs
    }
}

impl<'a> async_std::io::Write for DirectoryFileWriter<'a> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        /* check if the bytes fit into the size limit */
        if self.total_size.load(Ordering::Relaxed) > self.max_dir_size {
            self.get_mut().errored = true;
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "data limit exceeded",
            )));
        }

        /* check if it's not too late */
        if SystemTime::now() > self.expiration_time {
            self.get_mut().errored = true;
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "time limit expired",
            )));
        }

        // get a reference for total size
        let size_ref = self.total_size;

        /* write the bytes */
        let slf = self.get_mut();
        let res = async_std::io::Write::poll_write(Pin::new(&mut slf.file), cx, buf);

        /* log the bytes written */
        if let std::task::Poll::Ready(Ok(size)) = &res {
            size_ref.fetch_add(*size as u64, Ordering::Relaxed);
            slf.bytes_written += *size as u64;
        };

        res
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        async_std::io::Write::poll_flush(Pin::new(&mut self.get_mut().file), cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        async_std::io::Write::poll_close(Pin::new(&mut self.get_mut().file), cx)
    }
}

impl<'a> Drop for DirectoryFileWriter<'a> {
    fn drop(&mut self) {
        /* just a safety precausion forcing users of this struct to call finalize()

           we could technically implement the finalize() method in here, but it's async and that would be a pain
        */
        if !self.finalized {
            panic!("Dropping DirectoryFileWriter without calling finalize() is not allowed");
        }
    }
}

#[derive(Clone)]
pub struct DirectoryRegistry {
    real_sizes: Arc<Mutex<HashMap<String, Weak<Directory>>>>,
}

impl DirectoryRegistry {
    pub fn new() -> Self {
        Self {
            real_sizes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get(&self, directory_name: &str) -> anyhow::Result<Arc<Directory>> {
        let mut lock = self.real_sizes.lock().await;

        let res = lock.get(directory_name);
        if let Some(wk) = res {
            if let Some(rc) = wk.upgrade() {
                return Ok(rc);
            }
        }

        let dir = Directory::new(PathBuf::from(directory_name))?;
        let res = Arc::new(dir);
        lock.insert(directory_name.to_owned(), Arc::<Directory>::downgrade(&res));
        Ok(res)
    }
}
