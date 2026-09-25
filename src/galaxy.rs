use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read, Seek, SeekFrom},
    path::{Component, Path},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionMeta {
    pub namespace: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub dependencies: serde_json::Value,
}

pub fn inspect(bytes: &[u8], expected_sha: Option<&str>) -> Result<(CollectionMeta, [u8; 32])> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    verify_expected_digest(digest, expected_sha)?;
    inspect_archive(Cursor::new(bytes), digest)
}

pub fn inspect_path(path: &Path, expected_sha: Option<&str>) -> Result<(CollectionMeta, [u8; 32])> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    verify_expected_digest(digest, expected_sha)?;
    file.seek(SeekFrom::Start(0))?;
    inspect_archive(file, digest)
}

fn verify_expected_digest(digest: [u8; 32], expected_sha: Option<&str>) -> Result<()> {
    if let Some(expected) = expected_sha {
        if expected != hex(&digest) {
            anyhow::bail!(
                "sha256 mismatch: expected {expected}, actual {}",
                hex(&digest)
            )
        }
    }
    Ok(())
}

fn inspect_archive<R: Read + Seek>(
    reader: R,
    digest: [u8; 32],
) -> Result<(CollectionMeta, [u8; 32])> {
    let mut reader = reader;
    preflight_archive(&mut reader)?;
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let mut manifest = None;
    let mut files_manifest = None;
    let mut file_hashes = HashMap::new();
    let mut paths = HashSet::new();
    let mut count = 0usize;
    let mut total_size = 0u64;
    for entry in archive.entries().context("reading collection archive")? {
        let entry = entry?;
        count += 1;
        if count > 10_000 {
            anyhow::bail!("too many archive entries")
        }
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            anyhow::bail!("archive contains a non-regular file")
        }
        let size = entry.size();
        if size > 64 * 1024 * 1024 || total_size.saturating_add(size) > 256 * 1024 * 1024 {
            anyhow::bail!("archive decompressed size limit exceeded")
        }
        total_size = total_size.saturating_add(size);
        let path = entry.path()?.to_path_buf();
        if path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            anyhow::bail!("unsafe archive path")
        }
        let normalized = path.to_string_lossy().trim_start_matches("./").to_owned();
        if normalized.is_empty() || !paths.insert(normalized.clone()) {
            anyhow::bail!("duplicate or empty archive path")
        }
        if entry_type.is_dir() {
            continue;
        }
        if normalized == "MANIFEST.json" {
            if manifest.is_some() {
                anyhow::bail!("duplicate manifest")
            }
            let mut data = Vec::new();
            entry.take(1024 * 1024 + 1).read_to_end(&mut data)?;
            if data.len() > 1024 * 1024 {
                anyhow::bail!("MANIFEST.json is too large")
            }
            file_hashes.insert(normalized, hex(&Sha256::digest(&data)));
            manifest = Some(data);
        } else if normalized == "FILES.json" {
            let mut data = Vec::new();
            entry.take(4 * 1024 * 1024 + 1).read_to_end(&mut data)?;
            if data.len() > 4 * 1024 * 1024 {
                anyhow::bail!("FILES.json is too large")
            }
            file_hashes.insert(normalized, hex(&Sha256::digest(&data)));
            files_manifest = Some(data);
        } else {
            let mut hasher = Sha256::new();
            let mut reader = entry;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            file_hashes.insert(normalized, hex(&hasher.finalize()));
        }
    }
    let files_data = files_manifest.context("FILES.json not found")?;
    let data = manifest.context("MANIFEST.json not found")?;
    let raw: serde_json::Value = serde_json::from_slice(&data).context("invalid MANIFEST.json")?;
    validate_files(&raw, &files_data, &file_hashes)?;
    let collection_info = raw.get("collection_info").cloned().unwrap_or(raw);
    let meta: CollectionMeta =
        serde_json::from_value(collection_info).context("invalid collection_info")?;
    if !valid_name(&meta.namespace) || !valid_name(&meta.name) || !valid_version(&meta.version) {
        anyhow::bail!("invalid collection metadata")
    }
    if !meta.dependencies.is_object() {
        anyhow::bail!("collection dependencies must be an object")
    }
    Ok((meta, digest))
}

fn preflight_archive<R: Read + Seek>(reader: &mut R) -> Result<()> {
    const MAX_DECOMPRESSED_BYTES: u64 = 272 * 1024 * 1024;
    const MAX_EXTENSION_BYTES: u64 = 64 * 1024;
    reader.seek(SeekFrom::Start(0))?;
    let limited = GzDecoder::new(&mut *reader).take(MAX_DECOMPRESSED_BYTES + 1);
    let mut archive = tar::Archive::new(limited);
    let mut count = 0usize;
    let mut total_size = 0u64;
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        count += 1;
        if count > 10_000 {
            anyhow::bail!("too many archive entries")
        }
        let kind = entry.header().entry_type();
        let extension = kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions()
            || kind.is_gnu_longname()
            || kind.is_gnu_longlink();
        let size = entry.size();
        if extension {
            if size > MAX_EXTENSION_BYTES {
                anyhow::bail!("archive extension is too large")
            }
            if kind.is_pax_local_extensions() || kind.is_pax_global_extensions() {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                if data.split(|byte| *byte == b'\n').any(|line| {
                    line.iter()
                        .position(|byte| *byte == b' ')
                        .is_some_and(|space| line[space + 1..].starts_with(b"size="))
                }) {
                    anyhow::bail!("PAX size override is not supported")
                }
            } else {
                std::io::copy(&mut entry, &mut std::io::sink())?;
            }
        } else {
            if !(kind.is_file() || kind.is_dir()) {
                anyhow::bail!("archive contains a non-regular file")
            }
            if size > 64 * 1024 * 1024 || total_size.saturating_add(size) > 256 * 1024 * 1024 {
                anyhow::bail!("archive decompressed size limit exceeded")
            }
            total_size += size;
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
    }
    let mut limited = archive.into_inner();
    std::io::copy(&mut limited, &mut std::io::sink())?;
    if limited.limit() == 0 {
        anyhow::bail!("archive decompressed size limit exceeded")
    }
    drop(limited);
    reader.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn validate_files(
    manifest: &serde_json::Value,
    files_data: &[u8],
    hashes: &HashMap<String, String>,
) -> Result<()> {
    let files: serde_json::Value =
        serde_json::from_slice(files_data).context("invalid FILES.json")?;
    let entries = files
        .get("files")
        .and_then(serde_json::Value::as_array)
        .context("FILES.json has no files array")?;
    let mut declared = HashSet::new();
    for entry in entries {
        if entry.get("ftype").and_then(serde_json::Value::as_str) != Some("file") {
            continue;
        }
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .context("FILES.json entry has no name")?;
        let checksum = entry
            .get("chksum_sha256")
            .and_then(serde_json::Value::as_str)
            .context("FILES.json entry has no sha256")?;
        if !declared.insert(name) || hashes.get(name).map(String::as_str) != Some(checksum) {
            anyhow::bail!("FILES.json checksum or path mismatch")
        }
    }
    let expected_files: HashSet<_> = hashes
        .keys()
        .filter(|name| name.as_str() != "MANIFEST.json" && name.as_str() != "FILES.json")
        .map(String::as_str)
        .collect();
    if declared != expected_files {
        anyhow::bail!("FILES.json does not describe every archive file")
    }
    let expected = manifest
        .get("file_manifest_file")
        .and_then(|value| value.get("chksum_sha256"))
        .and_then(serde_json::Value::as_str)
        .context("MANIFEST.json has no FILES.json checksum")?;
    if hashes.get("FILES.json").map(String::as_str) != Some(expected) {
        anyhow::bail!("FILES.json does not match MANIFEST.json")
    }
    Ok(())
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn valid_version(s: &str) -> bool {
    s.len() <= 128 && semver::Version::parse(s).is_ok()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn archive(manifest: &str) -> Vec<u8> {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut compressed);
            let mut header = tar::Header::new_gnu();
            header.set_path("MANIFEST.json").unwrap();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, manifest.as_bytes()).unwrap();
            let mut files = tar::Header::new_gnu();
            files.set_path("FILES.json").unwrap();
            files.set_size(12);
            files.set_mode(0o644);
            files.set_cksum();
            tar.append(&files, &b"{\"files\":[]}"[..]).unwrap();
            tar.finish().unwrap();
        }
        compressed.finish().unwrap()
    }

    #[test]
    fn accepts_collection_manifest_and_checksum() {
        let files_checksum = hex(&Sha256::digest(b"{\"files\":[]}"));
        let bytes = archive(&format!(
            r#"{{"collection_info":{{"namespace":"engineering","name":"common","version":"1.2.3","dependencies":{{}}}},"file_manifest_file":{{"chksum_sha256":"{files_checksum}"}}}}"#
        ));
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let (meta, actual) = inspect(&bytes, Some(&hex(&digest))).unwrap();
        assert_eq!(meta.namespace, "engineering");
        assert_eq!(meta.name, "common");
        assert_eq!(meta.version, "1.2.3");
        assert_eq!(actual, digest);

        let temporary = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temporary.path(), &bytes).unwrap();
        let (from_file, file_digest) = inspect_path(temporary.path(), Some(&hex(&digest))).unwrap();
        assert_eq!(from_file.version, "1.2.3");
        assert_eq!(file_digest, digest);
    }

    #[test]
    fn rejects_bad_checksum_and_traversal() {
        let bytes = archive(
            r#"{"collection_info":{"namespace":"engineering","name":"common","version":"1.0.0"}}"#,
        );
        assert!(inspect(&bytes, Some("00")).is_err());
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = tar::Builder::new(&mut compressed);
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..17].copy_from_slice(b"../MANIFEST.json\0");
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &b"{}"[..]).unwrap();
        tar.finish().unwrap();
        drop(tar);
        let unsafe_archive = compressed.finish().unwrap();
        assert!(inspect(&unsafe_archive, None).is_err());
    }

    #[test]
    fn rejects_duplicate_manifests() {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = tar::Builder::new(&mut compressed);
        for _ in 0..2 {
            let mut header = tar::Header::new_gnu();
            header.set_path("MANIFEST.json").unwrap();
            header.set_size(2);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, &b"{}"[..]).unwrap();
        }
        let mut files = tar::Header::new_gnu();
        files.set_path("FILES.json").unwrap();
        files.set_size(12);
        files.set_mode(0o644);
        files.set_cksum();
        tar.append(&files, &b"{\"files\":[]}"[..]).unwrap();
        tar.finish().unwrap();
        drop(tar);
        assert!(inspect(&compressed.finish().unwrap(), None).is_err());
    }

    #[test]
    fn rejects_pax_size_override_before_reading_file() {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut compressed);
            tar.append_pax_extensions([("size", b"67108865".as_slice())])
                .unwrap();
            let mut header = tar::Header::new_ustar();
            header.set_path("payload.bin").unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            tar.get_mut().write_all(header.as_bytes()).unwrap();
            tar.finish().unwrap();
        }
        let bytes = compressed.finish().unwrap();
        assert!(inspect(&bytes, None)
            .unwrap_err()
            .to_string()
            .contains("PAX size override"));
    }

    #[test]
    fn rejects_large_pax_extension_before_tar_allocates_it() {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut compressed);
            let value = vec![b'x'; 64 * 1024];
            tar.append_pax_extensions([("comment", value.as_slice())])
                .unwrap();
            tar.finish().unwrap();
        }
        let bytes = compressed.finish().unwrap();
        assert!(inspect(&bytes, None)
            .unwrap_err()
            .to_string()
            .contains("archive extension is too large"));
    }

    #[test]
    fn permits_bounded_pax_metadata() {
        let mut compressed = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut compressed);
            tar.append_pax_extensions([("comment", b"hello".as_slice())])
                .unwrap();
            let mut header = tar::Header::new_ustar();
            header.set_path("readme.txt").unwrap();
            header.set_size(5);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, b"hello".as_slice()).unwrap();
            tar.finish().unwrap();
        }
        let bytes = compressed.finish().unwrap();
        assert!(preflight_archive(&mut Cursor::new(bytes)).is_ok());
    }
}
