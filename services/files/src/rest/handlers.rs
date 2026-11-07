use axum::{
    extract::{Extension, Multipart, Path as AxumUrlParams, Query},
    http::StatusCode,
    response::Response,
};
use exif::{In, Tag};
use hyper::HeaderMap;
use image::{ImageFormat, ImageReader};
use lib::{
    configs::uploads::UploadConfig,
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::{
        api_responses::synthesize_rest_response,
        custom_error::ApiError,
        models::{ApiResponseRest, AuthStatus, ForeignKey, UserId},
    },
};
use tokio::{
    fs::{File, create_dir_all, remove_file},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use uuid::Uuid;

use std::{
    env,
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};
use surrealdb::{
    Surreal,
    engine::remote::ws::Client,
    types::{RecordId, RecordIdKey},
};

use crate::{
    ThumbnailLocks,
    graphql::schemas::general::{
        Bucket, FileMeta, Key, ResolvedContainer, UploadedFile, UploadedFileResponse,
    },
};

#[derive(serde::Deserialize)]
pub struct ImageResizeParams {
    pub width: Option<u32>,
    pub height: Option<u32>,
}

pub async fn upload(
    AxumUrlParams(path): AxumUrlParams<String>,
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<AuthStatus>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    mut multipart: Multipart,
) -> Result<ApiResponseRest<Vec<UploadedFileResponse>>, ApiError> {
    let upload_dir = env::var("FILE_UPLOADS_DIR").map_err(|e| {
        tracing::error!("Missing FILE_UPLOADS_DIR environment variable: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    // --- Resolve the authenticated user to a RecordId<user_id> ---
    let user_fk_body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: auth_status.sub,
    };
    let user_fk = add_foreign_key_if_not_exists::<Arc<Surreal<Client>>, UserId>(&db, user_fk_body)
        .await
        .ok_or(ApiError::Unauthorized("Unauthorized".into()))?;

    let owner: RecordId = user_fk.id.clone();

    // --- Resolve and validate the path once, up front ---
    // This replaces the entire validation query and gives us `is_free` from the bucket.
    let resolved = match resolve_container(&db, &path, Some(&owner)).await {
        Ok(r) => r,
        Err(e) => {
            drain_multipart(&mut multipart).await;
            return Err(e);
        }
    };

    let is_premium = resolved.bucket_is_premium;

    create_dir_all(&upload_dir).await.map_err(|e| {
        tracing::error!("Failed to create upload directory: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    // --- Process fields, tracking everything we touch for rollback ---
    let mut responses: Vec<UploadedFileResponse> = Vec::new();
    let mut written_paths: Vec<PathBuf> = Vec::new();
    let mut created_ids: Vec<RecordId> = Vec::new();

    let loop_result: Result<(), ApiError> = async {
        while let Some(mut field) = multipart.next_field().await.map_err(|e| {
            tracing::error!("Multipart error: {}", e);
            ApiError::BadRequest("Invalid multipart payload".into())
        })? {
            let system_filename = Uuid::new_v4().to_string();
            let filepath = Path::new(&upload_dir).join(&system_filename);

            let field_name = field
                .name()
                .map(str::to_string)
                .unwrap_or_else(|| "unknown".into());
            let filename = field
                .file_name()
                .map(str::to_string)
                .unwrap_or_else(|| "unknown".into());
            let mime_type = field
                .content_type()
                .map(str::to_string)
                .unwrap_or_else(|| "application/octet-stream".into());

            // 1. Stream to disk, enforcing the cap.
            let total_size = write_field_to_disk(&mut field, &filepath, &cfg).await?;
            written_paths.push(filepath.clone());

            // 2. Single transaction: file row + belongs_to edge.
            let meta = FileMeta {
                name: filename,
                size: total_size,
                mime_type,
                system_filename: system_filename.clone(),
                is_premium,
                is_public: resolved.bucket_is_public,
            };

            let stored_file =
                create_file_record(&db, &owner, &meta, &resolved.bucket, resolved.key.as_ref())
                    .await?;

            let Some(file_id) = record_key_string(&stored_file.id) else {
                tracing::error!(id = ?stored_file.id, "file id is not a string record key");
                return Err(ApiError::Internal(anyhow::anyhow!("Invalid file id")));
            };

            created_ids.push(stored_file.id.clone());
            responses.push(UploadedFileResponse {
                field_name,
                file_name: stored_file.system_filename,
                file_id,
                original_filename: stored_file.name,
            });
        }
        Ok(())
    }
    .await;

    if let Err(e) = loop_result {
        rollback(&db, &written_paths, &created_ids).await;
        drain_multipart(&mut multipart).await;
        return Err(e);
    }

    Ok(synthesize_rest_response(
        &headers,
        &responses,
        StatusCode::CREATED,
    ))
}

pub async fn download_file(
    AxumUrlParams(key): AxumUrlParams<String>,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<Option<AuthStatus>>,
) -> Result<Response, ApiError> {
    let upload_dir = env::var("FILE_UPLOADS_DIR").map_err(|e| {
        tracing::error!("Missing FILE_UPLOADS_DIR: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    // Resolve path without ownership enforcement (auth is applied at the file level).
    let (container, file_name) = resolve_file_path(&db, &key, None).await?;
    let file_details = find_file_in_container(&db, &container, &file_name).await?;

    // Authorization gate for premium files.
    if file_details.is_premium || !file_details.is_public {
        match auth_status.as_ref() {
            Some(auth_status) => {
                let user = user_record_id(&db, auth_status).await?;
                if !user_has_access(&db, &user, &file_details).await? {
                    return Err(ApiError::Forbidden("Not Allowed!".into()));
                }
            }
            None => {
                return Err(ApiError::Forbidden("Not Allowed!".into()));
            }
        }
    }

    let path = Path::new(&upload_dir).join(&file_details.system_filename);
    let file = File::open(&path).await.map_err(|e| {
        tracing::error!(error = %e, path = %path.display(), "failed to open file");
        ApiError::NotFound("File not found".into())
    })?;

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", file_details.name),
        )
        .header("Content-Type", file_details.mime_type)
        .body(body)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build response");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })
}

pub async fn get_image(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    AxumUrlParams(key): AxumUrlParams<String>,
    Query(resize_params): Query<ImageResizeParams>,
    Extension(auth_status): Extension<Option<AuthStatus>>,
    Extension(thumbnail_locks): Extension<ThumbnailLocks>,
) -> Result<Response, ApiError> {
    let upload_dir = env::var("FILE_UPLOADS_DIR").map_err(|e| {
        tracing::error!("Missing FILE_UPLOADS_DIR: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let upload_dir = PathBuf::from(upload_dir);

    let (container, file_name) = resolve_file_path(&db, &key, None).await?;

    let file_details = find_file_in_container(&db, &container, &file_name).await?;

    // Authorization.
    if file_details.is_premium || !file_details.is_public {
        match auth_status.as_ref() {
            Some(auth_status) => {
                let user = user_record_id(&db, auth_status).await?;

                if !user_has_access(&db, &user, &file_details).await? {
                    return Err(ApiError::Forbidden("Not Allowed!".into()));
                }
            }
            None => {
                return Err(ApiError::Forbidden("Not Allowed!".into()));
            }
        }
    }

    let is_resized = resize_params.width.is_some() || resize_params.height.is_some();

    let (final_buffer, content_type) = if is_resized {
        let buffer = get_or_create_thumbnail(
            &upload_dir,
            &file_details.system_filename,
            &file_details.mime_type,
            resize_params.width,
            resize_params.height,
            &thumbnail_locks,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                filename = %file_details.system_filename,
                "failed to retrieve thumbnail"
            );

            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

        (buffer, "image/webp")
    } else {
        let path = upload_dir.join(&file_details.system_filename);

        let buffer = tokio::fs::read(&path).await.map_err(|e| {
            tracing::error!(
                error = %e,
                path = %path.display(),
                "failed to read image"
            );

            ApiError::NotFound("Image not found".into())
        })?;

        (buffer, file_details.mime_type.as_str())
    };

    let cache_control = if file_details.is_public && !file_details.is_premium {
        "public, max-age=86400, immutable"
    } else {
        "private, no-store"
    };

    Response::builder()
        .header("Content-Type", content_type)
        .header("Cache-Control", cache_control)
        .body(final_buffer.into())
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build response");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })
}

fn resize_image(
    buffer: &[u8],
    content_type: &str,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<Vec<u8>, StatusCode> {
    let format = match content_type {
        "image/jpeg" | "image/jpg" => ImageFormat::Jpeg,
        "image/png" => ImageFormat::Png,
        "image/webp" => ImageFormat::WebP,
        "image/gif" => ImageFormat::Gif,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let img = ImageReader::with_format(Cursor::new(buffer), format)
        .decode()
        .map_err(|e| {
            tracing::error!("Failed to decode image: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Apply EXIF orientation before resizing.
    let img = apply_exif_orientation(img, buffer);

    let resized = match (width, height) {
        (Some(w), Some(h)) => img.resize(w, h, image::imageops::FilterType::Lanczos3),
        (Some(w), None) => img.resize(w, u32::MAX, image::imageops::FilterType::Lanczos3),
        (None, Some(h)) => img.resize(u32::MAX, h, image::imageops::FilterType::Lanczos3),
        (None, None) => return Err(StatusCode::BAD_REQUEST),
    };

    let mut output = Cursor::new(Vec::new());

    resized
        .write_to(&mut output, ImageFormat::WebP)
        .map_err(|e| {
            tracing::error!("Failed to encode WebP image: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(output.into_inner())
}

fn apply_exif_orientation(img: image::DynamicImage, buffer: &[u8]) -> image::DynamicImage {
    let mut reader = BufReader::new(Cursor::new(buffer));
    let exif_reader = exif::Reader::new();

    let Ok(exif) = exif_reader.read_from_container(&mut reader) else {
        return img;
    };

    let Some(orientation) = exif.get_field(Tag::Orientation, In::PRIMARY) else {
        return img;
    };

    match orientation.value.get_uint(0) {
        Some(2) => img.fliph(),
        Some(3) => img.rotate180(),
        Some(4) => img.flipv(),
        Some(5) => img.rotate90().fliph(),
        Some(6) => img.rotate90(),
        Some(7) => img.rotate270().fliph(),
        Some(8) => img.rotate270(),
        _ => img, // 1 or unknown — no transform needed
    }
}

/// Resolve `bucket[/key[/subkey...]]` to DB records, validating ownership.
/// No filename — the container alone.
pub async fn resolve_container(
    db: &Surreal<Client>,
    path: &str,
    user: Option<&RecordId>, // Some(user) enforces ownership; None for public reads
) -> Result<ResolvedContainer, ApiError> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return Err(ApiError::BadRequest("path must include a bucket".into()));
    }

    let bucket_name = segments[0];
    let key_segments = &segments[1..];

    let bucket: Option<Bucket> = db
        .query("SELECT * FROM bucket WHERE name = $name LIMIT 1 FETCH owner")
        .bind(("name", bucket_name.to_string()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    let bucket = bucket.ok_or_else(|| {
        tracing::warn!(bucket = %bucket_name, "bucket not found");
        ApiError::NotFound(format!("bucket `{bucket_name}` not found"))
    })?;

    if let Some(user) = user {
        if bucket.owner.id != *user {
            tracing::warn!(bucket = %bucket_name, "user does not own bucket");
            return Err(ApiError::NotFound(format!(
                "bucket `{bucket_name}` not found"
            )));
        }
    };

    let mut parent: Option<RecordId> = None;

    for segment in key_segments {
        let key = find_key_under(db, segment, &bucket.id, parent.as_ref())
            .await?
            .ok_or_else(|| {
                tracing::warn!(key = %segment, "key not found under parent");
                ApiError::NotFound(format!("key `{segment}` not found"))
            })?;

        if let Some(user) = user {
            if key.owner.id != *user {
                tracing::warn!(key = %segment, "user does not own key");
                return Err(ApiError::NotFound(format!("key `{segment}` not found")));
            }
        }

        parent = Some(key.id);
    }

    Ok(ResolvedContainer {
        bucket: bucket.id,
        key: parent,
        bucket_is_premium: bucket.is_premium,
        bucket_is_public: bucket.is_public,
    })
}

/// For read endpoints: `bucket[/key...]/filename` → (container, filename).
pub async fn resolve_file_path(
    db: &Surreal<Client>,
    path: &str,
    user: Option<&RecordId>,
) -> Result<(ResolvedContainer, String), ApiError> {
    let (container_path, file_name) = path
        .rsplit_once('/')
        .ok_or_else(|| ApiError::BadRequest("path must be at least bucket/filename".into()))?;

    if file_name.is_empty() {
        return Err(ApiError::BadRequest("path must end with a filename".into()));
    }

    let container = resolve_container(db, container_path, user).await?;
    Ok((container, file_name.to_string()))
}

async fn find_key_under(
    db: &Surreal<Client>,
    name: &str,
    bucket: &RecordId,
    parent: Option<&RecordId>,
) -> Result<Option<Key>, ApiError> {
    let target = parent.unwrap_or(bucket);

    db.query(
        r#"
        SELECT *
        FROM ONLY (
            $parent
        )<-belongs_to<-(key WHERE name = $name)
        LIMIT 1
        FETCH owner;
        "#,
    )
    .bind(("name", name.to_string()))
    .bind(("parent", target.clone()))
    .await
    .map_err(ApiError::db)?
    .take(0)
    .map_err(ApiError::db)
}

pub async fn create_file_record(
    db: &Surreal<Client>,
    owner: &RecordId,
    meta: &FileMeta,
    bucket: &RecordId,
    key: Option<&RecordId>,
) -> Result<UploadedFile, ApiError> {
    let parent = key.cloned().unwrap_or_else(|| bucket.clone());

    let file: Option<UploadedFile> = db
        .query(
            r#"
            BEGIN TRANSACTION;

            LET $file = (SELECT VALUE id FROM (CREATE ONLY file CONTENT {
                owner:           $owner,
                name:            $name,
                size:            $size,
                mime_type:       $mime_type,
                system_filename: $system_filename,
                is_premium:         $is_premium,
                is_public:       $is_public,
            } RETURN AFTER));

            RELATE $file->belongs_to->$parent;

            RETURN (SELECT * FROM ONLY $file FETCH owner);

            COMMIT TRANSACTION;
            "#,
        )
        .bind(("owner", owner.clone()))
        .bind(("name", meta.name.clone()))
        .bind(("size", meta.size))
        .bind(("mime_type", meta.mime_type.clone()))
        .bind(("system_filename", meta.system_filename.clone()))
        .bind(("is_premium", meta.is_premium))
        .bind(("is_public", meta.is_public))
        .bind(("parent", parent))
        .await
        .map_err(ApiError::db)?
        .take(3)
        .map_err(ApiError::db)?;

    file.ok_or_else(|| {
        tracing::error!(system_filename = %meta.system_filename, "file create returned no row");
        ApiError::Internal(anyhow::anyhow!("Failed to create file record"))
    })
}

/// Stream a multipart field to disk, enforcing the small-upload cap.
/// Returns bytes written. On any error, the caller is responsible for
/// removing the partial file at `filepath`.
async fn write_field_to_disk(
    field: &mut axum::extract::multipart::Field<'_>,
    filepath: &Path,
    cfg: &Arc<UploadConfig>,
) -> Result<u64, ApiError> {
    let mut file = File::create(filepath).await.map_err(|e| {
        tracing::error!(error = %e, path = %filepath.display(), "failed to create file");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let mut total: u64 = 0;
    let upload_limit = cfg.max_upload_size * 1024 * 1024;

    while let Some(chunk) = field.chunk().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read chunk");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })? {
        total += chunk.len() as u64;
        if total > upload_limit {
            tracing::warn!(
                limit = upload_limit,
                "field exceeds small upload limit; client should use /multipart-upload/initiate"
            );
            return Err(ApiError::PayloadTooLarge(format!(
                "file exceeds {} byte limit; use multipart upload for larger files",
                upload_limit
            )));
        }
        file.write_all(&chunk).await.map_err(|e| {
            tracing::error!(error = %e, "failed to write chunk");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;
    }

    file.flush().await.map_err(|e| {
        tracing::error!(error = %e, "failed to flush file");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    Ok(total)
}

/// Drain remaining multipart fields so the client doesn't see ECONNRESET
/// when we bail out early. Time-bounded so a stalled client can't hang us.
async fn drain_multipart(multipart: &mut Multipart) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(Some(_)) = multipart.next_field().await {}
    })
    .await;
}

/// Undo everything this request wrote: delete the blobs, then the DB rows.
/// Failures during rollback are logged but not surfaced — the caller is
/// already returning an error, and a partial rollback is a monitoring problem,
/// not a client-facing one.
async fn rollback(db: &Surreal<Client>, paths: &[PathBuf], ids: &[RecordId]) {
    for path in paths {
        if let Err(e) = remove_file(path).await {
            tracing::error!(error = %e, path = %path.display(), "rollback: failed to remove file");
        }
    }

    if ids.is_empty() {
        return;
    }

    if let Err(e) = db.query("DELETE $ids").bind(("ids", ids.to_vec())).await {
        tracing::error!(error = %e, count = ids.len(), "rollback: failed to delete file records");
    }
}

fn record_key_string(id: &RecordId) -> Option<String> {
    match &id.key {
        RecordIdKey::String(s) => Some(s.clone()),
        _ => None,
    }
}

pub async fn user_record_id(
    db: &Arc<Surreal<Client>>,
    auth_status: &AuthStatus,
) -> Result<RecordId, ApiError> {
    let body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: auth_status.sub.clone(),
    };
    add_foreign_key_if_not_exists::<Arc<Surreal<Client>>, UserId>(db, body)
        .await
        .ok_or(ApiError::Unauthorized("Unauthorized".into()))
        .map(|fk| fk.id)
}

/// True if `user` bought the file or owns it.
async fn user_has_access(
    db: &Surreal<Client>,
    user: &RecordId,
    file: &UploadedFile,
) -> Result<bool, ApiError> {
    // Ownership check is cheap and local — do it first.
    if file.owner.id == *user {
        return Ok(true);
    }

    let bought: Option<UploadedFile> = db
        .query(
            r#"
            SELECT *
            FROM ONLY (
                $user
            )->bought->(file WHERE id = $file)
            LIMIT 1
            FETCH owner
            "#,
        )
        .bind(("user", user.clone()))
        .bind(("file", file.id.clone()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    Ok(bought.is_some())
}

pub async fn find_file_in_container(
    db: &Surreal<Client>,
    container: &ResolvedContainer,
    name: &str,
) -> Result<UploadedFile, ApiError> {
    let parent = container
        .key
        .clone()
        .unwrap_or_else(|| container.bucket.clone());
    tracing::debug!("parent: {:?}, name: {}", parent, name);

    let file: Option<UploadedFile> = db
        .query(
            r#"
            SELECT *
            FROM ONLY (
                $parent
            )<-belongs_to<-(file WHERE name = $name)
            LIMIT 1
            FETCH owner;
            "#,
        )
        .bind(("name", name.to_string()))
        .bind(("parent", parent))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    file.ok_or_else(|| {
        tracing::warn!(name, "file not found in container");
        ApiError::NotFound(format!("file `{name}` not found"))
    })
}

// Thumbnail Logic
fn thumbnail_filename(system_filename: &str, width: Option<u32>, height: Option<u32>) -> String {
    let dimensions = match (width, height) {
        (Some(w), Some(h)) => format!("{w}wx{h}h"),
        (Some(w), None) => format!("{w}w"),
        (None, Some(h)) => format!("{h}h"),
        (None, None) => unreachable!(),
    };

    format!("thumb-{system_filename}{dimensions}")
}

async fn get_thumbnail_lock(locks: &ThumbnailLocks, key: &str) -> Arc<Mutex<()>> {
    let mut registry = locks.lock().await;

    registry.retain(|_, lock| lock.strong_count() > 0);

    if let Some(lock) = registry.get(key).and_then(Weak::upgrade) {
        return lock;
    }

    let lock = Arc::new(Mutex::new(()));

    registry.insert(key.to_string(), Arc::downgrade(&lock));

    lock
}

async fn get_or_create_thumbnail(
    upload_dir: &Path,
    system_filename: &str,
    content_type: &str,
    width: Option<u32>,
    height: Option<u32>,
    locks: &ThumbnailLocks,
) -> anyhow::Result<Vec<u8>> {
    let thumbnail_name = thumbnail_filename(system_filename, width, height);

    let thumbnail_path = upload_dir.join(&thumbnail_name);

    // 1. Fast path: read existing thumbnail without locking.
    match tokio::fs::read(&thumbnail_path).await {
        Ok(buffer) => return Ok(buffer),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    // 2. Cache miss: obtain the thumbnail-specific lock.
    let lock = get_thumbnail_lock(locks, &thumbnail_name).await;

    let _guard = lock.lock().await;

    // 3. Double-check: another request may have generated it.
    match tokio::fs::read(&thumbnail_path).await {
        Ok(buffer) => return Ok(buffer),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    // 4. Read the original image.
    let original_path = upload_dir.join(system_filename);
    let buffer = tokio::fs::read(&original_path).await?;

    // 5. Generate WebP thumbnail.
    let resized = resize_image(&buffer, content_type, width, height)
        .map_err(|e| anyhow::anyhow!("Thumbnail generation failed: {e}"))?;

    // 6. Write to a unique temporary file in the same directory.
    let temp_path = upload_dir.join(format!("tmp-{}", uuid::Uuid::new_v4()));

    if let Err(e) = tokio::fs::write(&temp_path, &resized).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(e.into());
    }

    // 7. Publish the completed thumbnail.
    if let Err(e) = tokio::fs::rename(&temp_path, &thumbnail_path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;

        // Another process may have generated the thumbnail.
        match tokio::fs::read(&thumbnail_path).await {
            Ok(buffer) => return Ok(buffer),
            Err(_) => return Err(e.into()),
        }
    }

    Ok(resized)
}
