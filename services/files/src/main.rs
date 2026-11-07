mod database;
mod graphql;
mod grpc;
mod rest;
mod utils;

use std::{
    collections::HashMap,
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Extension},
    http::{HeaderMap, HeaderValue},
    middleware,
    routing::{get, post, put},
    serve,
};

use chrono::Duration as ChronoDuration;
use graphql::resolvers::query::Query;
use hyper::{
    Method, StatusCode,
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
};

use grpc::server::FilesServiceImplementation;
use lib::{
    configs::uploads::UploadConfig,
    integration::grpc::clients::files_service::files_service_server::FilesServiceServer,
    middleware::{
        auth::{
            grpc::{AuthMiddleware, AuthResponseMiddleware},
            rest::{handle_auth_with_refresh, handle_optional_auth},
        },
        headers::content::limit_by_content_length,
    },
};
use rest::handlers::{download_file, get_image, upload};
use surrealdb::{Surreal, engine::remote::ws::Client};
use tokio::sync::Mutex;
use tonic::transport::Server;
use tonic_middleware::{MiddlewareLayer, RequestInterceptorLayer};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use uuid::Uuid;

use crate::rest::multipart::{self, abort, complete, initiate, list_parts, part_url, upload_part};

pub type ThumbnailLocks = Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

async fn graphql_handler(
    schema: Extension<MySchema>,
    db: Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;
    let db = db.clone();
    let mut headers = headers.clone();

    let request_id = Uuid::new_v4();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );
    request = request.data(db);
    request = request.data(headers);

    let operation_name = request.operation_name.clone();

    // Log request info(I just want to deploy Files again)
    tracing::info!("Executing GraphQL request: {:?}", &operation_name);
    let start = std::time::Instant::now();

    // Execute the GraphQL request
    let response = schema.execute(request).await;

    let duration = start.elapsed();
    tracing::info!("{:?} request processed in {:?}", operation_name, duration);

    // Debug the response
    if response.errors.len() > 0 {
        tracing::error!("GraphQL Error: {:?}", response.errors);
    } else {
        tracing::info!("GraphQL request completed without errors");
    }

    // Convert GraphQL response into the Axum response type
    response.into()
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "files.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout = std::io::stdout
        .with_filter(|meta| {
            meta.target() != "h2::codec::framed_write" && meta.target() != "h2::codec::framed_read"
        })
        .with_max_level(tracing::Level::DEBUG); // Log to console at DEBUG level

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(stdout.and(non_blocking))
        .init();

    let connection_pool = database::connection::create_db_connection()
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to the database: {}", e);
            Error::new(
                ErrorKind::ConnectionAborted,
                "Failed to connect to the database",
            )
        })?;
    let db = Arc::new(connection_pool);
    let config = Arc::new(UploadConfig::from_env().map_err(|e| {
        tracing::error!("configuration error: {e:#}");
        e
    })?);

    // Thumbnail locks
    let thumbnail_locks: ThumbnailLocks = Arc::new(Mutex::new(HashMap::new()));

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ALLOWED_SERVICES_CORS not set")
    })?;
    let files_http_port = env::var("FILES_HTTP_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "FILES_HTTP_PORT not set")
    })?;
    let files_grpc_port = env::var("FILES_GRPC_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "FILES_GRPC_PORT not set")
    })?;
    let governor_burst_size = env::var("FILES_RATE_LIMIT_BURST_SIZE")
        .unwrap_or_else(|_| "20".to_string())
        .parse::<u32>()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(
                ErrorKind::Other,
                "FILES_RATE_LIMIT_BURST_SIZE must be a number",
            )
        })?;

    // Initialize the schema builder
    let mut schema_builder =
        Schema::build(Query::default(), Mutation::default(), EmptySubscription);

    // Disable introspection & limit query depth in production
    schema_builder = match deployment_env.as_str() {
        "prod" => schema_builder.disable_introspection().limit_depth(5),
        _ => schema_builder,
    };

    let schema = schema_builder.finish();

    let origins: Vec<HeaderValue> = allowed_services_cors
        .as_str()
        .split(",")
        .filter_map(|endpoint| endpoint.trim().parse::<HeaderValue>().ok())
        .collect();

    // Allow bursts with up to five requests per IP address
    // and replenishes one element every two seconds
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(governor_burst_size)
        .finish()
        .ok_or_else(|| {
            tracing::error!("Config Error: invalid governor configuration");
            Error::new(ErrorKind::InvalidInput, "Invalid governor configuration")
        })?;

    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    // a separate background task to clean up
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            tracing::info!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    let auth_required = Router::new()
        .route("/upload/{*path}", post(upload))
        .route_layer(middleware::from_fn(handle_auth_with_refresh))
        .route_layer(middleware::from_fn(limit_by_content_length))
        .layer(DefaultBodyLimit::disable());

    let auth_optional = Router::new()
        .route("/download/{*key}", get(download_file))
        .route("/view/{*key}", get(get_image))
        .route_layer(middleware::from_fn(handle_optional_auth));

    let multipart_control = Router::new()
        .route("/initiate", post(initiate))
        .route("/{upload_id}/parts/{part_number}/url", get(part_url))
        .route("/{upload_id}/parts", get(list_parts))
        .route("/{upload_id}/complete", post(complete))
        .route("/{upload_id}/abort", post(abort))
        .route_layer(middleware::from_fn(handle_auth_with_refresh));

    // Signed-URL receiver — no auth middleware, no body limit.
    let part_receiver = Router::new()
        .route("/multipart-upload/parts", put(upload_part))
        .layer(DefaultBodyLimit::disable());

    let app = Router::new()
        .nest("/multipart-upload", multipart_control)
        .merge(part_receiver)
        .merge(auth_required)
        .merge(auth_optional)
        .route("/", post(graphql_handler))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/ready", get(|| async { StatusCode::OK }))
        .layer(Extension(config.clone()))
        .layer(GovernorLayer::new(governor_conf))
        .layer(Extension(schema))
        .layer(Extension(db.clone()))
        .layer(Extension(thumbnail_locks))
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_headers([
                    AUTHORIZATION,
                    ACCEPT,
                    CONTENT_TYPE,
                    SET_COOKIE,
                    COOKIE,
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    ACCESS_CONTROL_ALLOW_HEADERS,
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    ACCESS_CONTROL_ALLOW_METHODS,
                    ACCESS_CONTROL_EXPOSE_HEADERS,
                ])
                .allow_credentials(true)
                .allow_methods(vec![Method::GET, Method::POST]),
        );

    multipart::spawn_session_sweeper(db.clone(), config.clone(), ChronoDuration::hours(24));

    // Set up the gRPC server
    let files_grpc = FilesServiceImplementation::new(db.clone());
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", files_grpc_port)
        .as_str()
        .parse()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(ErrorKind::Other, "gRPC address not set")
        })?;

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .layer(RequestInterceptorLayer::new(AuthMiddleware::default()))
            .layer(MiddlewareLayer::new(AuthResponseMiddleware::default()))
            .add_service(FilesServiceServer::new(files_grpc))
            .serve(grpc_address)
            .await
            .ok();
    });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", files_http_port)).await {
        Ok(http_listener) => {
            let _http_server = serve(
                http_listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create HTTP server: {}", e);
            })
            .ok();
        }
        Err(e) => {
            tracing::error!("Failed to create TCP listener: {}", e);
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                "Failed to create TCP listener",
            ));
        }
    };

    Ok(())
}
