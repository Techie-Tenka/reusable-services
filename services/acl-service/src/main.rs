mod database;
mod graphql;
mod grpc;
mod rest;
mod utils;

use std::{
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
    vec,
};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    Router,
    extract::Extension,
    http::{HeaderMap, HeaderName, HeaderValue},
    routing::{get, post},
    serve,
};

use axum_cookie::CookieLayer;
use graphql::resolvers::query::Query;
use grpc::server::AclServiceImplementation;
use hyper::{
    Method, StatusCode,
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
};
use rest::handlers::{exchange_code_for_token, oauth_callback_handler, verify_email_handler};
use rumqttc::v5::AsyncClient;
use surrealdb::{Surreal, engine::remote::ws::Client};
use tonic::transport::Server;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;

use lib::{
    integration::grpc::clients::acl_service::acl_server::AclServer, utils::mqtt::MqttClient,
};
use uuid::Uuid;

use crate::rest::handlers::{exchange_code_for_token_native, oauth_callback_native_handler};

type MySchema = Schema<Query, Mutation, EmptySubscription>;

pub struct AppState {
    pub mqtt_client: AsyncClient,
}

// TODO: I might extract this into own module to make main.rs leaner!
async fn graphql_handler(
    schema: Extension<MySchema>,
    db: Extension<Arc<Surreal<Client>>>,
    mqtt_client: Extension<Arc<AppState>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;

    let db = db.clone();
    let mut headers = headers.clone();
    let mqtt_client = mqtt_client.clone();
    let request_id = Uuid::new_v4();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );

    request = request.data(db);
    request = request.data(headers);
    request = request.data(mqtt_client);

    let operation_name = request.operation_name.clone();

    // Log request info(I just want to deploy ACL again)
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
    let file_appender = tracing_appender::rolling::daily("./logs", "acl.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout = std::io::stdout
        .with_filter(|meta| {
            meta.target() != "h2::codec::framed_write"
                && meta.target() != "h2::codec::framed_read"
                && meta.target() != "rumqttc::v5::state"
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
            Error::new(ErrorKind::ConnectionAborted, format!("{}", e))
        })?;
    let db = Arc::new(connection_pool);

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ALLOWED_SERVICES_CORS not set")
    })?;
    let acl_http_port = env::var("ACL_HTTP_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ACL_HTTP_PORT not set")
    })?;
    let acl_grpc_port = env::var("ACL_GRPC_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ACL_GRPC_PORT not set")
    })?;
    let mqtt_host = env::var("MQTT_HOST").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "MQTT_HOST not set")
    })?;
    let mqtt_port: u16 = env::var("MQTT_PORT")
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(ErrorKind::NotFound, "MQTT_PORT not set")
        })?
        .parse()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(
                ErrorKind::InvalidInput,
                "MQTT_PORT must be a valid port number",
            )
        })?;
    let governor_burst_size = env::var("ACL_RATE_LIMIT_BURST_SIZE")
        .unwrap_or_else(|_| "20".to_string())
        .parse::<u32>()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(
                ErrorKind::Other,
                "ACL_RATE_LIMIT_BURST_SIZE must be a number",
            )
        })?;

    // Initialize the schema builder
    let mut schema_builder = Schema::build(Query, Mutation, EmptySubscription);

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

    let (client, mut eventloop) = MqttClient::new("acl-service", &mqtt_host, mqtt_port).await?;

    tokio::spawn(async move { while let Ok(_event) = eventloop.poll().await {} });

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

    let shared_state = Arc::new(AppState {
        mqtt_client: client,
    });
    let x_client_platform: HeaderName = HeaderName::from_static("x-client-platform");

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/oauth/callback", get(oauth_callback_handler))
        .route("/oauth/callback/native", get(oauth_callback_native_handler))
        .route("/social-sign-in", post(exchange_code_for_token))
        .route(
            "/social-sign-in/native",
            post(exchange_code_for_token_native),
        )
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/ready", get(|| async { StatusCode::OK }))
        .route("/verify-email", get(verify_email_handler))
        .layer(GovernorLayer::new(governor_conf))
        .layer(Extension(shared_state))
        .layer(CookieLayer::strict())
        .layer(Extension(schema))
        .layer(Extension(db.clone()))
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
                    x_client_platform,
                ])
                .allow_credentials(true)
                .allow_methods(vec![Method::GET, Method::POST]),
        );

    // Set up the gRPC server
    let acl_grpc = AclServiceImplementation::new(db.clone());
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", acl_grpc_port)
        .as_str()
        .parse()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(ErrorKind::Other, "gRPC address not set")
        })?;

    tokio::spawn(async move {
        if let Err(e) = Server::builder()
            .add_service(AclServer::new(acl_grpc))
            .serve(grpc_address)
            .await
        {
            tracing::error!("Failed to start gRPC server: {}", e);
            std::process::exit(1);
        }
    });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", acl_http_port)).await {
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
