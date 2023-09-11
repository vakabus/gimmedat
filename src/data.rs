use anyhow::anyhow;
use async_std::fs::read_dir;
use async_std::fs::DirBuilder;
use async_std::fs::DirEntry;
use async_std::fs::File;
use async_std::fs::OpenOptions;
use async_std::io;
use async_std::path::Path;
use async_std::path::PathBuf;
use async_std::sync::Mutex;
use async_trait::async_trait;
use futures_lite::Stream;
use futures_lite::StreamExt;
use tokio::time::Instant;
use tracing::error;
use tracing::warn;

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::prelude::MetadataExt;
use std::pin::Pin;
use std::str;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::SystemTime;

use crate::capability::Capability;

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum FileRef {
    File,
    Dir,
}

async fn calculate_existing_dir_size(dir: &Path) -> anyhow::Result<u64> {
    async fn extend<A>(
        vec: &mut Vec<A>,
        mut stream: Pin<Box<dyn Stream<Item = io::Result<A>> + Send>>,
    ) -> io::Result<()> {
        while let Some(val) = stream.next().await {
            vec.push(val?);
        }
        Ok(())
    }

    let mut size = 0u64;
    let mut stack: Vec<DirEntry> = vec![];
    let mut count = 0;
    let start_time = Instant::now();
    extend(&mut stack, Box::pin(read_dir(dir).await?)).await?;

    while let Some(dir) = stack.pop() {
        // monitoring
        count += 1;
        if count == 1000 {
            warn!("traversing huge directory with more than 1000 files");
        }
        if start_time.elapsed() > Duration::from_secs(2) {
            error!("calculating total directory size takes more than 2 seconds, processed {} files so far", count);
            return Err(anyhow!(
                "directory has too many files, size calculation takes too long"
            ));
        }

        // accounting
        let metadata = dir.metadata().await.unwrap();
        size += metadata.size(); // file content
        size += dir.file_name().len() as u64; // length of the file name
        size += 4096; // constant overhead to account for metadata space of empty files

        // recurse into the directory
        if metadata.is_dir() {
            extend(&mut stack, Box::pin(read_dir(dir.path()).await?)).await?;
        }
    }

    Ok(size)
}

async fn assert_path_existence(path: &Path) {
    assert!(path.exists().await, "Directory does not exist");
    assert!(path.is_dir().await, "Path is not a directory");
}

async fn ensure_path_existence(path: &Path) {
    if !(path.exists().await && path.is_dir().await) {
        DirBuilder::new()
            .recursive(true)
            .create(path)
            .await
            .expect("creating directory should never fail");
    }
}

async fn create_fileref_set(path: &Path) -> HashMap<OsString, FileRef> {
    let entries: Vec<DirEntry> = read_dir(path)
        .await
        .unwrap()
        .collect::<Vec<std::io::Result<DirEntry>>>()
        .await
        .into_iter()
        .map(|v| v.unwrap())
        .collect();

    let mut files = HashMap::with_capacity(entries.len());
    for entry in entries {
        let metadata = entry.metadata().await.unwrap();

        if metadata.is_dir() {
            files.insert(entry.file_name(), FileRef::Dir);
        } else {
            files.insert(entry.file_name(), FileRef::File);
        }
    }
    files
}

async fn create_file_writer<'a>(
    dir: &'a UnsizedDirectory,
    uc: &Capability,
    filename: &'a str,
    expected_size: Option<u64>,
    uploaded_size: Option<&'a AtomicU64>,
) -> Result<DirectoryFileWriter<'a>, String> {
    /* check filename validity for Linux */
    if filename.contains('/') || filename.contains(0 as char) {
        return Err("invalid filename".to_owned());
    }

    assert_path_existence(&dir.path).await;
    let partial_name = get_partial_file_name(&dir.path, filename);

    let filename_os = OsString::from(filename);

    /* lock the filename we are working on */
    {
        /* check for finished file name collision & claim it if it's free */
        let mut names = dir.filenames.lock().await;
        if names.contains_key(&filename_os) {
            return Err("file already exists\n".to_owned());
        }
        names.insert(filename_os, FileRef::File);
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
    if let Some(uploaded_size) = uploaded_size {
        uploaded_size.fetch_add(4096, Ordering::Relaxed);
        uploaded_size.fetch_add(filename.len() as u64, Ordering::Relaxed);
    }

    /* create file writer object */
    Ok(DirectoryFileWriter::new(
        dir,
        uploaded_size,
        file,
        uc.size_limit(),
        filename,
        expected_size,
        uc.expiration_time(),
    ))
}

fn get_partial_file_name(path: &Path, name: &str) -> PathBuf {
    let name = format!("{name}$.partial");
    Path::join(path, name)
}

fn get_final_file_name(path: &Path, name: &str) -> PathBuf {
    Path::join(path, name)
}

struct UnsizedDirectory {
    path: PathBuf,
    filenames: Mutex<HashMap<OsString, FileRef>>,
}

impl UnsizedDirectory {
    pub async fn new(path: PathBuf) -> anyhow::Result<Self> {
        ensure_path_existence(&path).await;

        let filenames = Mutex::new(create_fileref_set(&path).await);

        Ok(Self { path, filenames })
    }

    async fn mark_upload_final(&self, name: &str) -> std::io::Result<()> {
        async_std::fs::rename(
            get_partial_file_name(&self.path, name),
            get_final_file_name(&self.path, name),
        )
        .await
    }

    pub async fn list_files(&self) -> Vec<(OsString, FileRef)> {
        let names = self.filenames.lock().await;
        names.clone().into_iter().collect()
    }
}

#[async_trait]
pub trait Directory {
    async fn list_files(&self) -> Vec<(OsString, FileRef)>;
    fn get_remaining_bytes(&self, cap: &Capability) -> u64 {
        u64::saturating_sub(cap.size_limit(), self.get_total_bytes())
    }
    fn get_total_bytes(&self) -> u64;

    async fn create_file_writer<'a>(
        &'a self,
        uc: &Capability,
        filename: &'a str,
        expected_size: Option<u64>,
    ) -> Result<DirectoryFileWriter<'a>, String>;

    fn is_size_limit_enforced(&self) -> bool;
}

#[async_trait]
impl Directory for UnsizedDirectory {
    fn is_size_limit_enforced(&self) -> bool {
        false
    }

    async fn list_files(&self) -> Vec<(OsString, FileRef)> {
        UnsizedDirectory::list_files(self).await
    }

    fn get_total_bytes(&self) -> u64 {
        0
    }

    async fn create_file_writer<'a>(
        &'a self,
        cap: &Capability,
        filename: &'a str,
        expected_size: Option<u64>,
    ) -> Result<DirectoryFileWriter<'a>, String> {
        create_file_writer(self, cap, filename, expected_size, None).await
    }
}

struct SizedDirectory {
    dir: UnsizedDirectory,
    real_size: AtomicU64,
}

impl SizedDirectory {
    pub async fn new(path: PathBuf) -> anyhow::Result<Self> {
        let size = AtomicU64::new(calculate_existing_dir_size(&path).await?);
        let dir = UnsizedDirectory::new(path).await?;

        Ok(Self {
            dir,
            real_size: size,
        })
    }
}

#[async_trait]
impl Directory for SizedDirectory {
    fn is_size_limit_enforced(&self) -> bool {
        true
    }

    async fn list_files(&self) -> Vec<(OsString, FileRef)> {
        self.dir.list_files().await
    }

    fn get_total_bytes(&self) -> u64 {
        self.real_size.load(Ordering::Relaxed)
    }

    async fn create_file_writer<'a>(
        &'a self,
        cap: &Capability,
        filename: &'a str,
        expected_size: Option<u64>,
    ) -> Result<DirectoryFileWriter<'a>, String> {
        create_file_writer(
            &self.dir,
            cap,
            filename,
            expected_size,
            Some(&self.real_size),
        )
        .await
    }
}

pub struct DirectoryFileWriter<'a> {
    dir: &'a UnsizedDirectory,
    filename: &'a str,
    file: File,

    /* internal state variables */
    errored: bool,
    finalized: bool,
    write_in_progress: bool,

    /* helper values for enforcing the size limit */
    total_size: Option<&'a AtomicU64>,
    expected_size: Option<u64>,
    bytes_written: u64,

    /* limits */
    max_dir_size: u64,
    expiration_time: SystemTime,
}

impl<'a> DirectoryFileWriter<'a> {
    fn new(
        dir: &'a UnsizedDirectory,
        total_size: Option<&'a AtomicU64>,
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
            write_in_progress: false,
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
        if let Some(total_size) = self.total_size {
            if self.max_dir_size <= total_size.load(Ordering::Relaxed) {
                msgs.push("data limit reached while uploading".to_owned());
            }
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
        let this = self.get_mut();
        let dummy = AtomicU64::new(0);
        let total_size = if let Some(total_size) = this.total_size {
            total_size
        } else {
            &dummy
        };

        /* reserve the bytes (CAS loop)
        - always Relaxed ordering, because we are working with just a single variable
          and there is no other operation that could be reorderd incorrectly
        - do this only once, before the actual write starts */
        if !this.write_in_progress {
            let mut current_value = total_size.load(Ordering::Relaxed);
            let addition = buf.len() as u64;
            loop {
                /* every time we loop, check if the bytes fit into the limit */
                if current_value + addition <= this.max_dir_size {
                    /* if they do, try to allocate */
                    match total_size.compare_exchange_weak(
                        current_value,
                        current_value + addition,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            /* allocation sucessfull, continue with the actual write */
                            break;
                        }
                        Err(real) => {
                            /* allocation unsucessfull, try again */
                            current_value = real;
                        }
                    }
                } else {
                    /* if the buffer does not fit, return error */
                    this.errored = true;
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "data limit exceeded",
                    )));
                }
            }
        }

        /* check if it's not too late */
        if SystemTime::now() > this.expiration_time {
            this.errored = true;
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "time limit expired",
            )));
        }

        /* write the bytes */
        this.write_in_progress = true;
        let res = async_std::io::Write::poll_write(Pin::new(&mut this.file), cx, buf);

        if let std::task::Poll::Ready(Ok(size)) = &res {
            /* this function does not necessarily write the whole buffer, so deallocate unused bytes */
            total_size.fetch_sub((buf.len() - size) as u64, Ordering::Relaxed);

            /* update internal state */
            this.write_in_progress = false;
            this.bytes_written += *size as u64;
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
    real_sizes: Arc<Mutex<HashMap<PathBuf, Weak<dyn Directory + Send + Sync>>>>,
}

impl DirectoryRegistry {
    pub fn new() -> Self {
        Self {
            real_sizes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get(&self, cap: &Capability) -> anyhow::Result<Arc<dyn Directory + Send + Sync>> {
        let mut lock = self.real_sizes.lock().await;

        let res = lock.get(cap.path());
        if let Some(wk) = res {
            if let Some(rc) = wk.upgrade() {
                if cap.is_enforcing_size_limit() && !rc.is_size_limit_enforced() {
                    // KNOWN PROBLEM: When there are two capabilities for the same directory, one of which does not enforce size limit and the other does, we can't work correctly.
                    //
                    // In situation, when:
                    //   1. unlimited capability makes a request
                    //   2. while processing the first request, we receive a request with limited capability for the same directory
                    // At the moment, we cannot upgrade the UnsizedDirectory object to SizedDirectory object transparently while
                    // there are active references.
                    return Err(anyhow!("Unable to provide a single directory with limited and unlimited size at the same time. Please try again."));
                }

                return Ok(rc);
            }
        }

        // was not present in the cache, create new object
        let dir: Arc<dyn Directory + Send + Sync> = if cap.is_enforcing_size_limit() {
            Arc::new(SizedDirectory::new(cap.path().to_owned()).await?)
        } else {
            Arc::new(UnsizedDirectory::new(cap.path().to_owned()).await?)
        };
        lock.insert(
            cap.path().to_owned(),
            Arc::<dyn Directory + Send + Sync>::downgrade(&dir),
        );
        Ok(dir)
    }
}
