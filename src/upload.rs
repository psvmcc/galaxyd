use base64::Engine;
use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UploadReadError {
    #[error("upload exceeds configured size limit")]
    TooLarge,
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Multipart(#[from] axum::extract::multipart::MultipartError),
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
        let encoded_limit = decoded_limit.div_ceil(3).saturating_mul(4);
        let mut pending = Vec::with_capacity(4);
        let mut encoded_size = 0usize;
        let mut decoded_size = 0usize;
        let mut saw_padding = false;
        while let Some(chunk) = field.chunk().await.map_err(UploadReadError::Multipart)? {
            let mut decoded_chunk = Vec::with_capacity(chunk.len().min(decoded_limit));
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
                if pending.len() != 4 {
                    continue;
                }
                let mut decoded = [0u8; 3];
                let decoded_len = base64::engine::general_purpose::STANDARD
                    .decode_slice(&pending, &mut decoded)
                    .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
                saw_padding = pending.contains(&b'=');
                decoded_size = decoded_size.saturating_add(decoded_len);
                if decoded_size > decoded_limit {
                    return Err(UploadReadError::TooLarge);
                }
                decoded_chunk.extend_from_slice(&decoded[..decoded_len]);
                pending.clear();
            }
            output
                .write_all(&decoded_chunk)
                .await
                .map_err(|error| UploadReadError::Invalid(error.to_string()))?;
        }
        if !pending.is_empty() {
            return Err(UploadReadError::Invalid("incomplete base64 data".into()));
        }
    } else {
        let mut written = 0usize;
        while let Some(chunk) = field.chunk().await.map_err(UploadReadError::Multipart)? {
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
    while let Some(chunk) = field.chunk().await.map_err(UploadReadError::Multipart)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(UploadReadError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        extract::Multipart,
        http::Request,
        routing::post,
        Router,
    };
    use http_body_util::BodyExt;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };
    use tower::ServiceExt;

    struct Chunks {
        values: VecDeque<Bytes>,
        pending: usize,
    }

    impl futures_core::Stream for Chunks {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.pending > 0 {
                self.pending -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending = 3;
            Poll::Ready(self.values.pop_front().map(Ok))
        }
    }

    async fn decode(mut multipart: Multipart) -> String {
        let field = multipart.next_field().await.unwrap().unwrap();
        let file = write_multipart_file(field, 1024).await.unwrap();
        String::from_utf8(std::fs::read(file.path()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn base64_padding_is_independent_of_transport_chunk_boundaries() {
        let prefix = "--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Transfer-Encoding: base64\r\n\r\n";
        for (encoded, expected) in [("YQ==", "a"), ("YWI=", "ab")] {
            for cut in 1..encoded.len() {
                let chunks = Chunks {
                    values: VecDeque::from([
                        Bytes::from(format!("{prefix}{}", &encoded[..cut])),
                        Bytes::from(encoded[cut..].to_owned()),
                        Bytes::from("\r\n--BOUNDARY--\r\n"),
                    ]),
                    pending: 0,
                };
                let response = Router::new()
                    .route("/", post(decode))
                    .oneshot(
                        Request::post("/")
                            .header("content-type", "multipart/form-data; boundary=BOUNDARY")
                            .body(Body::from_stream(chunks))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    expected,
                    "{encoded} split at {cut}"
                );
            }
        }
    }
}
