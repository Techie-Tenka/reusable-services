use axum::{extract::Request, http::header::CONTENT_LENGTH, middleware::Next, response::Response};

use crate::{configs::uploads::UploadConfig, utils::custom_error::ApiError};

/// Reject requests whose declared Content-Length exceeds `limit` before
/// any body is read. Returns a proper 413 response so clients can abort
/// cleanly instead of hitting a broken pipe.
pub async fn limit_by_content_length(req: Request, next: Next) -> Result<Response, ApiError> {
    let UploadConfig {
        max_upload_size, ..
    } = UploadConfig::from_env().map_err(|e| {
        tracing::error!("configuration error: {e:#}");
        ApiError::Internal(anyhow::anyhow!("Something went wrong."))
    })?;
    let declared = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let max_upload_size_bytes = max_upload_size * 1024 * 1024;

    match declared {
        Some(len) if len > (max_upload_size_bytes) => {
            tracing::warn!(
                declared = len,
                limit = max_upload_size,
                "upload rejected: request body too large"
            );
            Err(ApiError::PayloadTooLarge(format!(
                "request body exceeds {max_upload_size_bytes} bytes; use /multipart-upload/initiate for larger files"
            )))
        }
        None => {
            // Chunked transfer: no Content-Length to check. Refuse rather than
            // let it stream past the limit and die mid-upload.
            tracing::warn!("upload rejected: missing Content-Length");
            Err(ApiError::BadRequest(
                "Content-Length required on upload endpoints".into(),
            ))
        }
        _ => Ok(next.run(req).await),
    }
}
