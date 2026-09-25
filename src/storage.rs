use crate::galaxy::CollectionMeta;
use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::{primitives::ByteStream, Client};
use axum::body::Bytes;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use tokio_util::io::ReaderStream;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("version already exists")]
    AlreadyExists,
    #[error("publication not found")]
    NotFound,
}

const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_LEGACY_RECORD_BYTES: usize = 2 * 1024 * 1024;

fn encoded_record(record: &Record) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > MAX_RECORD_BYTES {
        anyhow::bail!("publication record exceeds size limit")
    }
    Ok(bytes)
}

pub(crate) fn validate_record(record: &Record) -> Result<()> {
    encoded_record(record).map(|_| ())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub meta: CollectionMeta,
    pub sha256: String,
    pub size: usize,
    pub artifact: String,
    #[serde(default)]
    pub published_at: u64,
}

pub type ArtifactStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send + 'static>>;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn publish(&self, record: &Record, bytes: &[u8]) -> Result<()>;
    async fn publish_file(&self, record: &Record, path: &Path) -> Result<()>;
    async fn get(&self, namespace: &str, name: &str, version: &str) -> Result<(Record, Vec<u8>)>;
    async fn record(&self, namespace: &str, name: &str, version: &str) -> Result<Record>;
    async fn stream(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
    ) -> Result<(Record, ArtifactStream)>;
    async fn records(&self) -> Result<Vec<Record>>;
    async fn ready(&self) -> bool;
    async fn put_task(&self, id: &str, bytes: &[u8]) -> Result<()>;
    async fn get_task(&self, id: &str) -> Result<Vec<u8>>;
    async fn tasks(&self) -> Result<Vec<(String, Vec<u8>)>>;
    async fn reconcile(&self, records: &[Record]) -> Result<()>;
}

#[derive(Clone)]
pub struct LocalStorage {
    root: Arc<PathBuf>,
    _lock: Arc<File>,
}
impl LocalStorage {
    pub fn new(root: PathBuf) -> Self {
        Self::try_new(root).expect("acquiring local storage process lock")
    }
    pub fn try_new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(".galaxyd.lock"))?;
        #[cfg(unix)]
        // SAFETY: flock only reads the valid file descriptor and does not retain its address.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!("local storage is already locked by another galaxyd process")
        }
        Ok(Self {
            root: Arc::new(root),
            _lock: Arc::new(lock),
        })
    }
    fn record_path(&self, namespace: &str, name: &str, version: &str) -> PathBuf {
        self.root
            .join("records")
            .join(namespace)
            .join(name)
            .join(format!("{version}.json"))
    }
    fn artifact_path(&self, r: &Record) -> PathBuf {
        self.root.join("artifacts").join(&r.artifact)
    }
    fn legacy_record_path(&self, namespace: &str, name: &str, version: &str) -> PathBuf {
        self.root
            .join("records")
            .join(format!("{namespace}-{name}-{version}.json"))
    }
}

pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: String,
}
impl S3Storage {
    pub async fn new(
        bucket: String,
        prefix: String,
        endpoint: Option<String>,
        region: Option<String>,
        force_path_style: bool,
    ) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_config::Region::new(region));
        }
        let base = loader.load().await;
        let mut builder =
            aws_sdk_s3::config::Builder::from(&base).force_path_style(force_path_style);
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        Self {
            client: Client::from_conf(builder.build()),
            bucket,
            prefix: prefix.trim_matches('/').to_owned(),
        }
    }
    fn key(&self, suffix: &str) -> String {
        if self.prefix.is_empty() {
            suffix.to_owned()
        } else {
            format!("{}/{}", self.prefix, suffix)
        }
    }
    fn record_key(&self, namespace: &str, name: &str, version: &str) -> String {
        self.key(&format!("records/{namespace}/{name}/{version}.json"))
    }
    fn artifact_key(&self, r: &Record) -> String {
        self.key(&format!("artifacts/{}", r.artifact))
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn publish(&self, record: &Record, bytes: &[u8]) -> Result<()> {
        let record_bytes = encoded_record(record)?;
        let artifact_key = self.artifact_key(record);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&artifact_key)
            .body(ByteStream::from(bytes.to_vec()))
            .content_type("application/gzip")
            .send()
            .await
            .context("uploading artifact")?;
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.record_key(
                &record.meta.namespace,
                &record.meta.name,
                &record.meta.version,
            ))
            .if_none_match("*")
            .body(ByteStream::from(record_bytes))
            .content_type("application/json")
            .send()
            .await;
        if let Err(error) = result {
            let duplicate = error
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 412);
            if duplicate {
                if let Err(cleanup_error) = self
                    .client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(&artifact_key)
                    .send()
                    .await
                {
                    tracing::warn!(error=%cleanup_error, artifact=%artifact_key, "failed to remove duplicate S3 artifact");
                }
                return Err(StorageError::AlreadyExists.into());
            }
            // The record write may have committed even if its response was lost. Keep this
            // uniquely named artifact for recovery instead of creating a visible record that
            // points to a deleted object.
            return Err(error.into());
        }
        Ok(())
    }
    async fn publish_file(&self, record: &Record, path: &Path) -> Result<()> {
        let record_bytes = encoded_record(record)?;
        let artifact_key = self.artifact_key(record);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&artifact_key)
            .body(ByteStream::from_path(path).await?)
            .content_type("application/gzip")
            .send()
            .await
            .context("uploading artifact")?;
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.record_key(
                &record.meta.namespace,
                &record.meta.name,
                &record.meta.version,
            ))
            .if_none_match("*")
            .body(ByteStream::from(record_bytes))
            .content_type("application/json")
            .send()
            .await;
        if let Err(error) = result {
            let duplicate = error
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 412);
            if duplicate {
                if let Err(cleanup_error) = self
                    .client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(&artifact_key)
                    .send()
                    .await
                {
                    tracing::warn!(error=%cleanup_error, artifact=%artifact_key, "failed to remove duplicate S3 artifact");
                }
                return Err(StorageError::AlreadyExists.into());
            }
            return Err(error.into());
        }
        Ok(())
    }
    async fn get(&self, namespace: &str, name: &str, version: &str) -> Result<(Record, Vec<u8>)> {
        validate_key(namespace, name, version)?;
        let key = self.record_key(namespace, name, version);
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await;
        let object = match object {
            Ok(object) => object,
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404) =>
            {
                match self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(self.key(&format!("records/{namespace}-{name}-{version}.json")))
                    .send()
                    .await
                {
                    Ok(object) => object,
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        return Err(StorageError::NotFound.into())
                    }
                    Err(error) => return Err(error).context("reading publication record"),
                }
            }
            Err(error) => return Err(error).context("reading publication record"),
        };
        let body = object.body.collect().await?.into_bytes();
        if body.len() > MAX_LEGACY_RECORD_BYTES {
            anyhow::bail!("publication record exceeds legacy size limit")
        }
        let record: Record = serde_json::from_slice(&body)?;
        if record.meta.namespace != namespace
            || record.meta.name != name
            || record.meta.version != version
        {
            anyhow::bail!("publication record identity mismatch")
        }
        let artifact = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.artifact_key(&record))
            .send()
            .await
            .map_err(|error| {
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404)
                {
                    StorageError::NotFound.into()
                } else {
                    anyhow::Error::from(error)
                }
            })?;
        let bytes = artifact.body.collect().await?.into_bytes().to_vec();
        verify_artifact(&record, &bytes)?;
        Ok((record, bytes))
    }
    async fn record(&self, namespace: &str, name: &str, version: &str) -> Result<Record> {
        validate_key(namespace, name, version)?;
        let key = self.record_key(namespace, name, version);
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await;
        let object = match object {
            Ok(object) => object,
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404) =>
            {
                match self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(self.key(&format!("records/{namespace}-{name}-{version}.json")))
                    .send()
                    .await
                {
                    Ok(object) => object,
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        return Err(StorageError::NotFound.into())
                    }
                    Err(error) => return Err(error).context("reading publication record"),
                }
            }
            Err(error) => return Err(error).context("reading publication record"),
        };
        let body = object.body.collect().await?.into_bytes();
        if body.len() > MAX_LEGACY_RECORD_BYTES {
            anyhow::bail!("publication record exceeds legacy size limit")
        }
        let record: Record = serde_json::from_slice(&body)?;
        if record.meta.namespace != namespace
            || record.meta.name != name
            || record.meta.version != version
        {
            anyhow::bail!("publication record identity mismatch")
        }
        Ok(record)
    }
    async fn stream(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
    ) -> Result<(Record, ArtifactStream)> {
        let record = self.record(namespace, name, version).await?;
        let artifact = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.artifact_key(&record))
            .send()
            .await
            .map_err(|error| {
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404)
                {
                    StorageError::NotFound.into()
                } else {
                    anyhow::Error::from(error)
                }
            })?;
        if artifact
            .content_length()
            .is_some_and(|size| size != record.size as i64)
        {
            anyhow::bail!("artifact size does not match publication record")
        }
        Ok((
            record,
            Box::pin(ReaderStream::new(artifact.body.into_async_read())),
        ))
    }
    async fn records(&self) -> Result<Vec<Record>> {
        let mut result = Vec::new();
        let mut token = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(self.key("records/"));
            if let Some(token) = token {
                request = request.continuation_token(token);
            }
            let page = request.send().await?;
            if let Some(objects) = page.contents {
                for object in objects {
                    if object
                        .size
                        .is_some_and(|size| size > MAX_LEGACY_RECORD_BYTES as i64)
                    {
                        anyhow::bail!(
                            "publication record exceeds legacy size limit: {:?}",
                            object.key
                        )
                    }
                    if let Some(key) = object.key {
                        let body = self
                            .client
                            .get_object()
                            .bucket(&self.bucket)
                            .key(key)
                            .send()
                            .await?
                            .body
                            .collect()
                            .await?
                            .into_bytes();
                        if body.len() > MAX_LEGACY_RECORD_BYTES {
                            anyhow::bail!("publication record exceeds legacy size limit")
                        }
                        result.push(serde_json::from_slice(&body)?);
                    }
                }
            }
            token = page.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        Ok(result)
    }
    async fn ready(&self) -> bool {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .is_ok()
    }
    async fn put_task(&self, id: &str, bytes: &[u8]) -> Result<()> {
        validate_task_id(id)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(&format!("tasks/{id}.json")))
            .body(ByteStream::from(bytes.to_vec()))
            .content_type("application/json")
            .send()
            .await?;
        Ok(())
    }
    async fn get_task(&self, id: &str) -> Result<Vec<u8>> {
        validate_task_id(id)?;
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(&format!("tasks/{id}.json")))
            .send()
            .await
            .map_err(|error| {
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404)
                {
                    StorageError::NotFound.into()
                } else {
                    anyhow::Error::from(error)
                }
            })?;
        let bytes = object.body.collect().await?.into_bytes();
        if bytes.len() > 64 * 1024 {
            anyhow::bail!("import task exceeds size limit")
        }
        Ok(bytes.to_vec())
    }
    async fn tasks(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let prefix = self.key("tasks/");
        let mut result = Vec::new();
        let mut token = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(value) = token {
                request = request.continuation_token(value);
            }
            let page = request.send().await?;
            if let Some(objects) = page.contents {
                for object in objects {
                    if object.size.is_some_and(|size| size > 64 * 1024) {
                        tracing::warn!(key=?object.key, "ignoring oversized import task");
                        continue;
                    }
                    let Some(key) = object.key else { continue };
                    let Some(id) = key
                        .strip_prefix(&prefix)
                        .and_then(|value| value.strip_suffix(".json"))
                    else {
                        continue;
                    };
                    if validate_task_id(id).is_err() {
                        continue;
                    }
                    let bytes = self
                        .client
                        .get_object()
                        .bucket(&self.bucket)
                        .key(&key)
                        .send()
                        .await?
                        .body
                        .collect()
                        .await?
                        .into_bytes()
                        .to_vec();
                    if bytes.len() <= 64 * 1024 {
                        result.push((id.to_owned(), bytes));
                    }
                }
            }
            token = page.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        Ok(result)
    }
    async fn reconcile(&self, records: &[Record]) -> Result<()> {
        let referenced: HashSet<String> = records
            .iter()
            .map(|record| self.artifact_key(record))
            .collect();
        let prefix = self.key("artifacts/");
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(24 * 60 * 60) as i64;
        let mut token = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(value) = token {
                request = request.continuation_token(value);
            }
            let page = request.send().await?;
            if let Some(objects) = page.contents {
                for object in objects {
                    let Some(key) = object.key else { continue };
                    let old_enough = object
                        .last_modified
                        .is_some_and(|value| value.secs() < cutoff);
                    if old_enough && !referenced.contains(&key) {
                        self.client
                            .delete_object()
                            .bucket(&self.bucket)
                            .key(&key)
                            .send()
                            .await?;
                        tracing::info!(artifact=%key, "removed orphaned S3 artifact");
                    }
                }
            }
            token = page.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        Ok(())
    }
}
#[async_trait]
impl Storage for LocalStorage {
    async fn publish(&self, record: &Record, bytes: &[u8]) -> Result<()> {
        let storage = self.clone();
        let record = record.clone();
        let bytes = bytes.to_vec();
        tokio::task::spawn_blocking(move || storage.publish_sync(&record, &bytes)).await?
    }
    async fn publish_file(&self, record: &Record, path: &Path) -> Result<()> {
        let storage = self.clone();
        let record = record.clone();
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || storage.publish_file_sync(&record, &path)).await?
    }
    async fn get(&self, namespace: &str, name: &str, version: &str) -> Result<(Record, Vec<u8>)> {
        let storage = self.clone();
        let namespace = namespace.to_owned();
        let name = name.to_owned();
        let version = version.to_owned();
        tokio::task::spawn_blocking(move || storage.get_sync(&namespace, &name, &version)).await?
    }
    async fn record(&self, namespace: &str, name: &str, version: &str) -> Result<Record> {
        let storage = self.clone();
        let namespace = namespace.to_owned();
        let name = name.to_owned();
        let version = version.to_owned();
        tokio::task::spawn_blocking(move || storage.record_sync(&namespace, &name, &version))
            .await?
    }
    async fn stream(
        &self,
        namespace: &str,
        name: &str,
        version: &str,
    ) -> Result<(Record, ArtifactStream)> {
        let record = self.record(namespace, name, version).await?;
        let file = tokio::fs::File::open(self.artifact_path(&record))
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound.into()
                } else {
                    anyhow::Error::from(error)
                }
            })?;
        if file.metadata().await?.len() != record.size as u64 {
            anyhow::bail!("artifact size does not match publication record")
        }
        Ok((record, Box::pin(ReaderStream::new(file))))
    }
    async fn records(&self) -> Result<Vec<Record>> {
        let dir = self.root.join("records");
        if !tokio::fs::try_exists(&dir).await? {
            return Ok(vec![]);
        }
        tokio::task::spawn_blocking(move || read_records(&dir)).await?
    }
    async fn ready(&self) -> bool {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            std::fs::create_dir_all(root.as_ref())?;
            let probe = tempfile::NamedTempFile::new_in(root.as_ref())?;
            probe.as_file().sync_all()?;
            Ok(())
        })
        .await
        .is_ok_and(|result| result.is_ok())
    }
    async fn put_task(&self, id: &str, bytes: &[u8]) -> Result<()> {
        validate_task_id(id)?;
        let directory = self.root.join("tasks");
        tokio::fs::create_dir_all(&directory).await?;
        let temporary = tempfile::NamedTempFile::new_in(&directory)?;
        tokio::fs::write(temporary.path(), bytes).await?;
        temporary.as_file().sync_all()?;
        std::fs::rename(temporary.path(), directory.join(format!("{id}.json")))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }
    async fn get_task(&self, id: &str) -> Result<Vec<u8>> {
        validate_task_id(id)?;
        let path = self.root.join("tasks").join(format!("{id}.json"));
        let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound.into()
            } else {
                anyhow::Error::from(error)
            }
        })?;
        if metadata.len() > 64 * 1024 {
            anyhow::bail!("import task exceeds size limit")
        }
        Ok(tokio::fs::read(path).await?)
    }
    async fn tasks(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let directory = self.root.join("tasks");
        if !tokio::fs::try_exists(&directory).await? {
            return Ok(Vec::new());
        }
        tokio::task::spawn_blocking(move || {
            let mut tasks = Vec::new();
            for entry in std::fs::read_dir(directory)? {
                let path = entry?.path();
                let Some(id) = path.file_stem().and_then(|value| value.to_str()) else {
                    continue;
                };
                if path.extension().and_then(|value| value.to_str()) != Some("json")
                    || validate_task_id(id).is_err()
                {
                    continue;
                }
                if std::fs::metadata(&path)?.len() > 64 * 1024 {
                    tracing::warn!(task=%path.display(), "ignoring oversized import task");
                    continue;
                }
                tasks.push((id.to_owned(), std::fs::read(&path)?));
            }
            Ok(tasks)
        })
        .await?
    }
    async fn reconcile(&self, records: &[Record]) -> Result<()> {
        let referenced: HashSet<_> = records
            .iter()
            .map(|record| record.artifact.clone())
            .collect();
        let directory = self.root.join("artifacts");
        if !tokio::fs::try_exists(&directory).await? {
            return Ok(());
        }
        tokio::task::spawn_blocking(move || {
            let cutoff = std::time::SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(24 * 60 * 60))
                .unwrap_or(std::time::UNIX_EPOCH);
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if !referenced.contains(name)
                    && entry
                        .metadata()?
                        .modified()
                        .is_ok_and(|modified| modified < cutoff)
                {
                    std::fs::remove_file(&path)?;
                    tracing::info!(artifact=%path.display(), "removed orphaned local artifact");
                }
            }
            Ok(())
        })
        .await?
    }
}

impl LocalStorage {
    fn record_sync(&self, namespace: &str, name: &str, version: &str) -> Result<Record> {
        validate_key(namespace, name, version)?;
        let data = std::fs::read(self.record_path(namespace, name, version))
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    std::fs::read(self.legacy_record_path(namespace, name, version))
                } else {
                    Err(error)
                }
            })
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound.into()
                } else {
                    anyhow::Error::from(error)
                }
            })?;
        if data.len() > MAX_LEGACY_RECORD_BYTES {
            anyhow::bail!("publication record exceeds legacy size limit")
        }
        let record: Record = serde_json::from_slice(&data)?;
        if record.meta.namespace != namespace
            || record.meta.name != name
            || record.meta.version != version
        {
            anyhow::bail!("publication record identity mismatch")
        }
        Ok(record)
    }
    fn publish_sync(&self, record: &Record, bytes: &[u8]) -> Result<()> {
        let record_bytes = encoded_record(record)?;
        validate_key(
            &record.meta.namespace,
            &record.meta.name,
            &record.meta.version,
        )?;
        let record_dir = self
            .root
            .join("records")
            .join(&record.meta.namespace)
            .join(&record.meta.name);
        std::fs::create_dir_all(&record_dir)?;
        std::fs::create_dir_all(self.root.join("artifacts"))?;
        let final_artifact = self.artifact_path(record);
        let mut artifact = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&final_artifact)?;
        artifact.write_all(bytes)?;
        artifact.sync_all()?;
        let record_tmp = tempfile::NamedTempFile::new_in(&record_dir)?;
        let rp = self.record_path(
            &record.meta.namespace,
            &record.meta.name,
            &record.meta.version,
        );
        {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(record_tmp.path())?;
            file.write_all(&record_bytes)?;
            file.sync_all()?;
        }
        match std::fs::hard_link(record_tmp.path(), &rp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&final_artifact);
                return Err(StorageError::AlreadyExists.into());
            }
            Err(error) => {
                let _ = std::fs::remove_file(&final_artifact);
                return Err(error.into());
            }
        }
        File::open(&record_dir)?.sync_all()?;
        File::open(self.root.join("artifacts"))?.sync_all()?;
        let _ = std::fs::remove_file(record_tmp.path());
        Ok(())
    }
    fn publish_file_sync(&self, record: &Record, source: &Path) -> Result<()> {
        let record_bytes = encoded_record(record)?;
        validate_key(
            &record.meta.namespace,
            &record.meta.name,
            &record.meta.version,
        )?;
        let record_dir = self
            .root
            .join("records")
            .join(&record.meta.namespace)
            .join(&record.meta.name);
        std::fs::create_dir_all(&record_dir)?;
        std::fs::create_dir_all(self.root.join("artifacts"))?;
        let final_artifact = self.artifact_path(record);
        let mut source = File::open(source)?;
        let mut artifact = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&final_artifact)?;
        let copied = std::io::copy(&mut source, &mut artifact)?;
        if copied != record.size as u64 {
            let _ = std::fs::remove_file(&final_artifact);
            anyhow::bail!("artifact size changed during publication")
        }
        artifact.sync_all()?;
        let record_tmp = tempfile::NamedTempFile::new_in(&record_dir)?;
        {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(record_tmp.path())?;
            file.write_all(&record_bytes)?;
            file.sync_all()?;
        }
        let record_path = self.record_path(
            &record.meta.namespace,
            &record.meta.name,
            &record.meta.version,
        );
        match std::fs::hard_link(record_tmp.path(), &record_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&final_artifact);
                return Err(StorageError::AlreadyExists.into());
            }
            Err(error) => {
                let _ = std::fs::remove_file(&final_artifact);
                return Err(error.into());
            }
        }
        File::open(&record_dir)?.sync_all()?;
        File::open(self.root.join("artifacts"))?.sync_all()?;
        Ok(())
    }
    fn get_sync(&self, namespace: &str, name: &str, version: &str) -> Result<(Record, Vec<u8>)> {
        let r = self.record_sync(namespace, name, version)?;
        let b = std::fs::read(self.artifact_path(&r)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound.into()
            } else {
                anyhow::Error::from(error)
            }
        })?;
        verify_artifact(&r, &b)?;
        Ok((r, b))
    }
}

fn validate_key(namespace: &str, name: &str, version: &str) -> Result<()> {
    if [namespace, name, version].iter().any(|part| {
        part.is_empty()
            || part.len() > 128
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
            || part.contains("..")
    }) {
        anyhow::bail!("invalid publication key")
    }
    Ok(())
}

fn validate_task_id(id: &str) -> Result<()> {
    if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        anyhow::bail!("invalid task id")
    }
    Ok(())
}

fn verify_artifact(record: &Record, bytes: &[u8]) -> Result<()> {
    if bytes.len() != record.size || crate::galaxy::hex(&Sha256::digest(bytes)) != record.sha256 {
        anyhow::bail!("artifact integrity check failed")
    }
    Ok(())
}

fn read_records(root: &Path) -> Result<Vec<Record>> {
    let mut pending = vec![root.to_path_buf()];
    let mut out = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|x| x.to_str()) == Some("json") {
                if std::fs::metadata(&path)?.len() > MAX_LEGACY_RECORD_BYTES as u64 {
                    anyhow::bail!(
                        "publication record exceeds legacy size limit: {}",
                        path.display()
                    )
                }
                out.push(serde_json::from_slice(&std::fs::read(path)?)?);
            }
        }
    }
    Ok(out)
}

pub async fn build(config: &crate::config::StorageConfig) -> Result<Arc<dyn Storage>> {
    match config {
        crate::config::StorageConfig::Local { path } => {
            Ok(Arc::new(LocalStorage::try_new(path.clone())?))
        }
        crate::config::StorageConfig::S3 {
            bucket,
            prefix,
            endpoint,
            region,
            force_path_style,
        } => Ok(Arc::new(
            S3Storage::new(
                bucket.clone(),
                prefix.clone(),
                endpoint.clone(),
                region.clone(),
                *force_path_style,
            )
            .await,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galaxy::CollectionMeta;

    fn record() -> Record {
        Record {
            meta: CollectionMeta {
                namespace: "engineering".into(),
                name: "common".into(),
                version: "1.0.0".into(),
                dependencies: serde_json::json!({}),
            },
            sha256: crate::galaxy::hex(&Sha256::digest(b"test")),
            size: 4,
            artifact: "engineering-common-1.0.0.tar.gz".into(),
            published_at: 0,
        }
    }

    #[tokio::test]
    async fn local_storage_round_trip_and_duplicate_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_path_buf());
        let record = record();
        storage.publish(&record, b"test").await.unwrap();
        let (loaded, bytes) = storage.get("engineering", "common", "1.0.0").await.unwrap();
        assert_eq!(loaded.meta.name, "common");
        assert_eq!(bytes, b"test");
        assert!(storage.publish(&record, b"other").await.is_err());
        assert_eq!(storage.records().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn local_storage_starts_empty_and_becomes_ready() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().join("nested"));
        assert!(storage.records().await.unwrap().is_empty());
        assert!(storage.ready().await);
    }

    #[test]
    fn local_storage_rejects_second_process_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _first = LocalStorage::try_new(dir.path().to_path_buf()).unwrap();
        assert!(LocalStorage::try_new(dir.path().to_path_buf()).is_err());
    }

    #[tokio::test]
    async fn concurrent_publication_has_exactly_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_path_buf());
        let mut first = record();
        first.artifact = "first.tar.gz".into();
        first.sha256 = crate::galaxy::hex(&Sha256::digest(b"first"));
        first.size = 5;
        let mut second = first.clone();
        second.artifact = "second.tar.gz".into();
        second.sha256 = crate::galaxy::hex(&Sha256::digest(b"second"));
        second.size = 6;
        let a = storage.clone();
        let b = storage.clone();
        let (one, two) = tokio::join!(a.publish(&first, b"first"), b.publish(&second, b"second"));
        assert_ne!(one.is_ok(), two.is_ok());
        assert_eq!(storage.records().await.unwrap().len(), 1);
        assert_eq!(
            std::fs::read_dir(dir.path().join("artifacts"))
                .unwrap()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn structured_keys_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_path_buf());
        let mut first = record();
        first.meta.namespace = "a".into();
        first.meta.name = "b-c".into();
        let mut second = first.clone();
        second.meta.namespace = "a-b".into();
        second.meta.name = "c".into();
        second.artifact = "second.tar.gz".into();
        storage.publish(&first, b"test").await.unwrap();
        storage.publish(&second, b"test").await.unwrap();
        assert_eq!(storage.records().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn oversized_record_is_rejected_before_publication_but_legacy_data_is_retained() {
        let directory = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(directory.path().to_path_buf());
        let mut record = record();
        record.meta.dependencies = serde_json::json!({"engineering.extra": "x".repeat(70_000)});
        assert!(storage.publish(&record, b"test").await.is_err());
        assert!(!directory
            .path()
            .join("artifacts")
            .join(&record.artifact)
            .exists());

        let path = storage.record_path("engineering", "common", "1.0.0");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(directory.path().join("artifacts")).unwrap();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let artifact = directory.path().join("artifacts").join(&record.artifact);
        std::fs::write(&artifact, b"test").unwrap();
        std::fs::File::open(&artifact)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600),
            ))
            .unwrap();
        let records = storage.records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert!(storage
            .record("engineering", "common", "1.0.0")
            .await
            .is_ok());
        storage.reconcile(&records).await.unwrap();
        assert!(artifact.exists());
    }
}
