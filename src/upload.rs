use base64::Engine;
use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UploadReadError {
    #[error("upload exceeds configured size limit")]
    TooLarge,
    #[error("{0}")]
    Invalid(String),
}

pub(crate) async fn write_multipart_file(
    mut field: axum::extract::multipart::Field<'_>,
    decoded_limit: usize,
) -> Result<tempfile::NamedTempFile, UploadReadError> {
    let encoded = field
        .headers()
        .get("content-transfer-encoding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("base64"));
    let temporary = tempfile::NamedTempFile::new()
        .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
    let reopened = temporary
        .reopen()
        .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
    let mut output = tokio::fs::File::from_std(reopened);
    if encoded {
        let encoded_limit = decoded_limit.saturating_mul(2).saturating_add(4096);
        let mut pending = Vec::new();
        let mut encoded_size = 0usize;
        let mut decoded_size = 0usize;
        let mut saw_padding = false;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|error| UploadReadError::Invalid(error.to_string()))?
        {
            for byte in chunk
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
            {
                if saw_padding {
                    return Err(UploadReadError::Invalid(
                        "base64 data follows padding".into(),
                    ));
                }
                encoded_size = encoded_size.saturating_add(1);
                if encoded_size > encoded_limit {
                    return Err(UploadReadError::TooLarge);
                }
                pending.push(byte);
            }
            let full_groups = pending.len() / 4 * 4;
            let process_size = if let Some(padding) = pending.iter().position(|byte| *byte == b'=')
            {
                saw_padding = true;
                padding / 4 * 4
            } else {
                full_groups
            };
            if process_size > 0 {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&pending[..process_size])
                    .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
                decoded_size = decoded_size.saturating_add(decoded.len());
                if decoded_size > decoded_limit {
                    return Err(UploadReadError::TooLarge);
                }
                output
                    .write_all(&decoded)
                    .await
                    .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
                pending.drain(..process_size);
            }
        }
        if !pending.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&pending)
                .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
            decoded_size = decoded_size.saturating_add(decoded.len());
            if decoded_size > decoded_limit {
                return Err(UploadReadError::TooLarge);
            }
            output
                .write_all(&decoded)
                .await
                .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
        }
    } else {
        let mut written = 0usize;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|error| UploadReadError::Invalid(error.to_string()))?
        {
            written = written.saturating_add(chunk.len());
            if written > decoded_limit {
                return Err(UploadReadError::TooLarge);
            }
            output
                .write_all(&chunk)
                .await
                .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
        }
    }
    output
        .flush()
        .await
        .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
    output
        .sync_data()
        .await
        .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
    Ok(temporary)
}

pub(crate) async fn read_small_multipart_field(
    mut field: axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<Vec<u8>, UploadReadError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| UploadReadError::Invalid(error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(UploadReadError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
