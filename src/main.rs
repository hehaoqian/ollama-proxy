// This will be our simplified main.rs file without the unused functions

use bytes::Bytes;
use chrono::Local;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod logger;
#[cfg(test)]
mod logger_tests;
mod size_parser;
mod time_parser;

use logger::Logger;
use time_parser::parse_time_string;

// A simple type alias for convenience
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// Command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 11434, env = "PROXY_OLLAMA_PORT")]
    port: u16,

    /// Ollama server URL
    #[arg(
        short,
        long,
        default_value = "http://localhost:11434",
        env = "PROXY_OLLAMA_URL"
    )]
    ollama_url: String,

    /// Output log file (if not specified, logs go to stdout only)
    #[arg(short, long, env = "PROXY_OLLAMA_LOG_FILE")]
    log_file: Option<PathBuf>,

    /// API key required for model management endpoints (create, copy, delete, pull, push)
    #[arg(short, long, env = "PROXY_OLLAMA_API_KEY")]
    api_key: Option<String>,

    /// List of allowed IP addresses (comma-separated). If specified, only these IPs can access the server.
    /// Example: --allowed-ips "127.0.0.1,192.168.1.5"
    #[arg(long, env = "PROXY_OLLAMA_ALLOWED_IPS")]
    allowed_ips: Option<String>,

    /// Enable HTTPS mode. If not set, server will use HTTP
    #[arg(long, env = "PROXY_OLLAMA_HTTPS")]
    https: bool,

    /// TLS certificate file path (required when HTTPS is enabled)
    #[arg(long, env = "PROXY_OLLAMA_CERT_FILE")]
    cert_file: Option<PathBuf>,

    /// TLS private key file path (required when HTTPS is enabled)
    #[arg(long, env = "PROXY_OLLAMA_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Host address to listen on (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1", env = "PROXY_OLLAMA_HOST")]
    host: String,

    /// Maximum log file size before rotation (default: 10MB)
    /// Supports human-readable formats like "10MB", "1GB", "500KB", etc.
    #[arg(long, default_value = "10MB", env = "PROXY_OLLAMA_LOG_ROTATE_SIZE")]
    log_rotate_size: String,

    /// Maximum number of rotated log files to keep (default: 0, unlimited)
    /// When this limit is reached, the oldest log files will be deleted
    #[arg(long, default_value_t = 0, env = "PROXY_OLLAMA_MAX_LOG_FILES")]
    max_log_files: u32,

    /// Minimum `keep_alive` time for model (default: none)
    /// Supports time formats like "30s", "5m", "1h30m", "3h1m5s", "-1s" (infinite)
    /// This overrides `keep_alive` in client requests if they are lower than this value
    #[arg(long, env = "PROXY_OLLAMA_MIN_KEEP_ALIVE")]
    min_keep_alive: Option<String>,
}

// Function to create a boxed response body from a string
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Create JSON response
fn json_response<T: Serialize>(data: &T, status: StatusCode) -> Response<BoxBody> {
    match serde_json::to_string(data) {
        Ok(json) => Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(full(json))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(full("Error serializing response"))
            .unwrap(),
    }
}

// Ollama server configuration
struct OllamaConfig {
    base_url: String,
    logger: Arc<Logger>,
    api_key: Option<String>,
    allowed_ips: Option<Vec<std::net::IpAddr>>,
    min_keep_alive_seconds: Option<i64>, // Store as seconds, negative means infinite
}

impl OllamaConfig {
    fn new(
        base_url: String,
        logger: Arc<Logger>,
        api_key: Option<String>,
        allowed_ips: Option<String>,
        min_keep_alive: Option<String>,
    ) -> Self {
        // Parse the allowed IPs string into a vector of IpAddr
        let allowed_ips = allowed_ips.map(|ips_str| {
            ips_str
                .split(',')
                .filter_map(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
                .collect::<Vec<_>>()
        });

        // Parse min_keep_alive string if provided
        let min_keep_alive_seconds =
            min_keep_alive.and_then(|time_str| match parse_time_string(&time_str) {
                Ok(seconds) => {
                    // Don't log here, will log in server startup
                    Some(seconds)
                }
                Err(e) => {
                    eprintln!("Warning: Could not parse min_keep_alive time: {e}");
                    None
                }
            });

        Self {
            base_url,
            logger,
            api_key,
            allowed_ips,
            min_keep_alive_seconds,
        }
    }

    // Build a full URI for an Ollama API endpoint
    fn build_uri(&self, path: &str) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        // Handle the root path specially to avoid double slashes
        let uri_str = format!("http://{}{}", self.base_url, path);
        uri_str
            .parse::<hyper::Uri>()
            .inspect_err(|_e| println!("Parse \"{path}\" fails"))
    }

    // Check if an IP address is allowed
    fn is_ip_allowed(&self, client_ip: &SocketAddr) -> bool {
        // If no allowlist is configured, allow all IPs
        if self.allowed_ips.is_none() {
            return true;
        }

        // Check if client IP is in the allowlist
        if let Some(ref allowed_ips) = self.allowed_ips {
            allowed_ips.contains(&client_ip.ip())
        } else {
            true
        }
    }
}

// Helper function to create an error response
fn create_error_response(status: StatusCode, message: String) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .body(full(message))
        .unwrap()
}

// Build the URI for an Ollama request
fn build_ollama_uri(
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
    let uri = ollama_config.build_uri(path)?;
    Ok(uri)
}

// Copy headers from source to target
fn copy_headers(
    source: &hyper::HeaderMap<hyper::header::HeaderValue>,
    target: &mut hyper::HeaderMap<hyper::header::HeaderValue>,
) {
    for (name, value) in source {
        // Skip Authorization header when forwarding requests to Ollama
        if name != hyper::header::AUTHORIZATION {
            target.insert(name.clone(), value.clone());
        }
    }
}

// Proxy an API request to Ollama
async fn proxy_to_ollama<B>(
    req: Request<B>,
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
    client_ip: &SocketAddr,
) -> Result<Response<BoxBody>, hyper::Error>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + std::fmt::Debug,
{
    ollama_config
        .logger
        .log(&format!(
            "Proxying request to Ollama: {} {}",
            req.method(),
            path
        ))
        .await;

    // Try to read the body
    let (parts, body) = req.into_parts();
    let maybe_body_bytes = match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();

            // Log detailed request in JSON format
            log_detailed_json(
                &ollama_config.logger,
                "request",
                &parts.method,
                path,
                None,
                &bytes,
                client_ip,
                &parts.headers,
            )
            .await;

            Some(bytes)
        }
        Err(e) => {
            let err_msg = format!("Error collecting request body: {e:?}");
            ollama_config.logger.log(&err_msg).await;
            None
        }
    };

    // Build the full URI
    let uri = match build_ollama_uri(path, ollama_config) {
        Ok(uri) => uri,
        Err(e) => {
            let err_msg = format!("Error parsing URI for path {path}: {e}");
            ollama_config.logger.log(&err_msg).await;
            return Ok(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid URI".to_string(),
            ));
        }
    };

    // Create client
    let client = Client::builder(TokioExecutor::new()).build_http();

    // Build request to forward
    let mut request_builder = Request::builder().uri(uri).method(parts.method);

    // Copy headers
    if let Some(headers) = request_builder.headers_mut() {
        copy_headers(&parts.headers, headers);
    }

    // Add body if it exists
    let forwarded_req = if let Some(body_bytes) = maybe_body_bytes {
        request_builder.body(Full::new(body_bytes).boxed()).unwrap()
    } else {
        request_builder
            .body(Full::new(Bytes::new()).boxed())
            .unwrap()
    };

    // Send to Ollama
    match client.request(forwarded_req).await {
        Ok(ollama_resp) => {
            // Build response
            let (parts, body) = ollama_resp.into_parts();
            let status = parts.status;

            // Collect the body
            match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();

                    // Log detailed response in JSON format
                    log_detailed_json(
                        &ollama_config.logger,
                        "response",
                        &Method::GET, // Response doesn't have a method, using GET as placeholder
                        path,
                        Some(status),
                        &bytes,
                        client_ip,
                        &parts.headers,
                    )
                    .await;

                    // Build our response
                    let mut builder = Response::builder().status(status);

                    // Copy headers
                    if let Some(headers) = builder.headers_mut() {
                        copy_headers(&parts.headers, headers);
                    }

                    Ok(builder.body(full(bytes)).unwrap())
                }
                Err(e) => {
                    let err_msg = format!("Error collecting Ollama response body: {e}");
                    ollama_config.logger.log(&err_msg).await;
                    Ok(create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error collecting response from Ollama".to_string(),
                    ))
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Error forwarding request to Ollama: {e}");
            ollama_config.logger.log(&err_msg).await;
            Ok(create_error_response(
                StatusCode::BAD_GATEWAY,
                format!("Error forwarding request to Ollama: {e}"),
            ))
        }
    }
}

// Helper function to log incoming requests
async fn log_request(logger: &Logger, method: &Method, path: &str, client_ip: &SocketAddr) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger
        .log(&format!("[{now}] {client_ip} {method} {path}"))
        .await;
}

// Helper function to log responses
async fn log_response(
    logger: &Logger,
    method: &Method,
    path: &str,
    status: &StatusCode,
    client_ip: &SocketAddr,
) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger
        .log(&format!(
            "[{now}] {client_ip} {method} {path} - {}",
            status.as_u16()
        ))
        .await;
}

// Handle 404 Not Found responses
fn handle_not_found() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(full(r#"{"error":"Not Found"}"#))
        .unwrap()
}

// Check if request is authenticated - returns true if API key is not required or if it matches
fn is_authenticated(
    req: &Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> bool {
    // If no API key is configured, allow all requests
    if ollama_config.api_key.is_none() {
        return true;
    }

    // Check for Authorization header
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            // Format expected is "Bearer <api_key>"
            if let Some(api_key) = auth_str.strip_prefix("Bearer ") {
                return Some(api_key.to_string()) == ollama_config.api_key;
            }
        }
    }

    false
}

// Handle unauthorized responses
fn handle_unauthorized() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .header("WWW-Authenticate", "Bearer")
        .body(full(r#"{"error":"Unauthorized - API key required"}"#))
        .unwrap()
}

// Helper to check if a request is an unload model request
fn is_unload_model_request(json: &serde_json::Value) -> bool {
    // Per Ollama docs, an empty prompt (or no prompt) with keep_alive: 0 unloads a model

    // Check if keep_alive is 0 as a number or string like "0s", "0m", "0h"
    fn is_zero_value(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Number(n) if n.as_i64() == Some(0) => true,
            serde_json::Value::String(s) => s == "0" || s == "0s" || s == "0m" || s == "0h",
            _ => false,
        }
    }

    // If keep_alive is not 0, then this is definitely not an unload request
    let keep_alive_is_zero = json.get("keep_alive").is_some_and(is_zero_value)
        || json
            .get("options")
            .and_then(|o| o.as_object())
            .and_then(|o| o.get("keep_alive"))
            .is_some_and(is_zero_value);

    if !keep_alive_is_zero {
        return false;
    }

    // According to Ollama API docs, either:
    // 1. No prompt field at all, or
    // 2. An empty prompt field
    // combined with keep_alive: 0 indicates an unload request
    let prompt_is_empty = match json.get("prompt") {
        Some(prompt) => prompt.as_str().is_some_and(str::is_empty),
        None => true, // No prompt field is valid for unload request
    };

    prompt_is_empty
}

// Extract and log model information from generate request
async fn log_model_info(json: &serde_json::Value, logger: &Logger, client_ip: &SocketAddr) {
    if let Some(model) = json.get("model").and_then(|m| m.as_str()) {
        let is_unload_request = is_unload_model_request(json);

        if is_unload_request {
            logger
                .log(&format!(
                    "Unloading model from memory from {client_ip}: {model}"
                ))
                .await;
        } else {
            logger
                .log(&format!(
                    "Forwarding generate request to Ollama from {client_ip} for model: {model}"
                ))
                .await;
        }
    }
}

// Create a fallback response for when Ollama is unavailable
fn create_generate_fallback_response() -> Response<BoxBody> {
    let response = serde_json::json!({
        "model": "unknown",
        "created_at": Local::now().to_rfc3339(),
        "response": "Mock response (Ollama server unavailable)",
        "done": true
    });
    json_response(&response, StatusCode::OK)
}

// Handle the special case of a generate request with model unloading instructions
async fn handle_generate_with_model_info(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
    client_ip: &SocketAddr,
) -> Response<BoxBody> {
    // Save the headers for potential authentication check before consuming the request
    let headers = req.headers().clone();

    // Try to examine the body to log info without consuming it
    let (_parts, body) = req.into_parts();
    let maybe_body_bytes = match body.collect().await {
        Ok(collected) => Some(collected.to_bytes()),
        Err(e) => {
            let err_msg = format!("Error collecting request body for logging: {e}");
            ollama_config.logger.log(&err_msg).await;
            None
        }
    };

    // If we have the body bytes, check for unload request and authentication
    let mut modified_body = None;
    if let Some(ref body_bytes) = maybe_body_bytes {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
            // Check if this is an unload request
            if is_unload_model_request(&json) {
                // For unload requests, we need to check authentication using the API key
                // If no API key is configured, allow all requests
                let is_auth = if let Some(ref api_key) = ollama_config.api_key {
                    // Check for Authorization header
                    if let Some(auth_header) = headers.get("Authorization") {
                        if let Ok(auth_str) = auth_header.to_str() {
                            // Format expected is "Bearer <api_key>"
                            if let Some(key) = auth_str.strip_prefix("Bearer ") {
                                key == api_key
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    true // No API key required
                };

                // Unload requests require authentication
                if !is_auth {
                    ollama_config
                        .logger
                        .log(&format!(
                            "Unauthorized attempt to unload model from {client_ip}"
                        ))
                        .await;
                    return handle_unauthorized();
                }

                // Log that we're unloading a model (authenticated)
                if let Some(model) = json.get("model").and_then(|m| m.as_str()) {
                    ollama_config
                        .logger
                        .log(&format!(
                            "Unloading model from memory (authenticated) from {client_ip}: {model}"
                        ))
                        .await;
                }
            } else {
                // Normal generate request, just log it
                log_model_info(&json, &ollama_config.logger, client_ip).await;

                // If min_keep_alive is set and this is not an unload request, potentially modify keep_alive
                if let Some(min_seconds) = ollama_config.min_keep_alive_seconds {
                    // Only apply if min_seconds is positive (not infinite)
                    if min_seconds > 0 {
                        let mut modified_json = json.clone();
                        let mut was_modified = false;

                        // Apply min_keep_alive to top-level keep_alive
                        if let Some(keep_alive) = modified_json.get("keep_alive") {
                            let should_modify = match keep_alive {
                                serde_json::Value::Number(n) => {
                                    // Only modify if keep_alive is not 0 (would be unload) and is less than min_seconds
                                    if let Some(current) = n.as_i64() {
                                        current > 0 && current < min_seconds
                                    } else {
                                        false
                                    }
                                }
                                serde_json::Value::String(s) => {
                                    // Try to parse as time string
                                    if let Ok(current) = parse_time_string(s) {
                                        current > 0 && current < min_seconds
                                    } else {
                                        false
                                    }
                                }
                                _ => false,
                            };

                            if should_modify {
                                // Modify the JSON with the minimum keep_alive value
                                if let Some(obj) = modified_json.as_object_mut() {
                                    obj.insert(
                                        "keep_alive".to_string(),
                                        serde_json::Value::Number(min_seconds.into()),
                                    );
                                    was_modified = true;

                                    ollama_config.logger
                                        .log(&format!(
                                            "Applied minimum keep_alive of {min_seconds}s to request from {client_ip}"
                                        ))
                                        .await;
                                }
                            }
                        }

                        // Also check options.keep_alive
                        if let Some(options) = modified_json.get_mut("options") {
                            if let Some(obj) = options.as_object_mut() {
                                if let Some(keep_alive) = obj.get("keep_alive") {
                                    let should_modify_option = match keep_alive {
                                        serde_json::Value::Number(n) => {
                                            if let Some(current) = n.as_i64() {
                                                current > 0 && current < min_seconds
                                            } else {
                                                false
                                            }
                                        }
                                        serde_json::Value::String(s) => {
                                            if let Ok(current) = parse_time_string(s) {
                                                current > 0 && current < min_seconds
                                            } else {
                                                false
                                            }
                                        }
                                        _ => false,
                                    };

                                    if should_modify_option {
                                        obj.insert(
                                            "keep_alive".to_string(),
                                            serde_json::Value::Number(min_seconds.into()),
                                        );
                                        was_modified = true;

                                        ollama_config.logger
                                            .log(&format!(
                                                "Applied minimum keep_alive of {min_seconds}s to options in request from {client_ip}"
                                            ))
                                            .await;
                                    }
                                }
                            }
                        }

                        // If we modified the JSON, serialize it to a new body
                        if was_modified {
                            if let Ok(new_body) = serde_json::to_vec(&modified_json) {
                                modified_body = Some(Bytes::from(new_body));
                            }
                        }
                    }
                }
            }
        }
    }

    // Create a new request with the body we read for Ollama
    let uri = ollama_config
        .build_uri(path)
        .expect("Failed to build URI for generate endpoint");

    let req = Request::builder()
        .uri(uri)
        .method(Method::POST)
        .body(
            Full::new(if let Some(modified) = modified_body {
                modified
            } else if let Some(bytes) = maybe_body_bytes {
                bytes
            } else {
                Bytes::new()
            })
            .boxed(),
        )
        .expect("Failed to create request");

    // Forward the request directly to Ollama
    if let Ok(response) = proxy_to_ollama(req, path, ollama_config, client_ip).await {
        response
    } else {
        // Fallback to mock response if Ollama is unavailable
        ollama_config
            .logger
            .log(&format!(
                "Failed to get response from Ollama for {client_ip}, using mock response"
            ))
            .await;
        create_generate_fallback_response()
    }
}

// Generic handler for Ollama API endpoints with fallback responses
async fn handle_ollama_endpoint_with_fallback<F>(
    method: Method,
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
    log_message: &str,
    client_ip: &SocketAddr,
    fallback_generator: F,
) -> Response<BoxBody>
where
    F: FnOnce() -> Response<BoxBody>,
{
    ollama_config.logger.log(log_message).await;

    // Create a request with no body
    let uri = ollama_config
        .build_uri(path)
        .expect("Failed to build URI for Ollama endpoint");

    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::new()).boxed())
        .expect("Failed to create request");

    // Forward the request directly to Ollama
    if let Ok(response) = proxy_to_ollama(req, path, ollama_config, client_ip).await { response } else {
        // Fallback to mock response if Ollama is unavailable
        ollama_config
            .logger
            .log("Failed to get response from Ollama, using fallback response")
            .await;
        fallback_generator()
    }
}

// Function to handle proxy errors consistently
fn handle_proxy_error(e: &hyper::Error) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(full(format!("Error: {e}")))
        .unwrap()
}

// Handle model listing endpoint with fallback
async fn handle_models_endpoint(
    ollama_config: &Arc<OllamaConfig>,
    client_ip: &SocketAddr,
) -> Response<BoxBody> {
    handle_ollama_endpoint_with_fallback(
        Method::GET,
        "/api/tags",
        ollama_config,
        &format!("Forwarding request to list models to Ollama from {client_ip}"),
        client_ip,
        || {
            // Simulate a list of models
            let models = serde_json::json!({
                "models": [
                    {
                        "name": "llama2",
                        "modified_at": "2023-08-02T17:02:23Z",
                        "size": 3_791_730_298_u64,
                        "digest": "sha256:a2...",
                        "details": {
                            "format": "gguf",
                            "family": "llama",
                            "parameter_size": "7B",
                            "quantization_level": "Q4_0",
                        },
                    },
                    {
                        "name": "mistral",
                        "modified_at": "2023-11-20T12:15:30Z",
                        "size": 4_356_823_129_u64,
                        "digest": "sha256:b1...",
                        "details": {
                            "format": "gguf",
                            "family": "mistral",
                            "parameter_size": "7B",
                            "quantization_level": "Q5_K",
                        },
                    },
                ],
            });
            json_response(&models, StatusCode::OK)
        },
    )
    .await
}

// Handle authenticated model management endpoints
async fn handle_model_management_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
    operation: &str,
    client_ip: &SocketAddr,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config) {
        ollama_config
            .logger
            .log(&format!(
                "Unauthorized request from {client_ip} for operation: {operation}"
            ))
            .await;
        return handle_unauthorized();
    }

    // Log the operation
    let operation_description = format!("model {operation}");
    ollama_config
        .logger
        .log(&format!(
            "Forwarding {operation_description} request to Ollama from {client_ip}"
        ))
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, path, ollama_config, client_ip)
        .await
        .unwrap_or_else(|e| handle_proxy_error(&e))
}

// Forward any API request to Ollama (default handler)
async fn forward_to_ollama(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
    client_ip: &SocketAddr,
) -> Response<BoxBody> {
    ollama_config
        .logger
        .log(&format!(
            "Forwarding request to Ollama from {client_ip}: {path}"
        ))
        .await;

    proxy_to_ollama(req, path, ollama_config, client_ip)
        .await
        .unwrap_or_else(|e| handle_proxy_error(&e))
}

// Handle API endpoints based on their route pattern
// This unified function routes requests to appropriate specialized handlers
async fn handle_api_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
    client_ip: &SocketAddr,
) -> Response<BoxBody> {
    // Extract method and path components for routing
    let method = req.method().clone();
    let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (method, path_parts.as_slice()) {
        // Generate endpoint - Forward with model info handling
        (Method::POST, ["api", "generate" | "chat" | "embed" | "embeddings" ])=> {
            handle_generate_with_model_info(req, ollama_config, path, client_ip).await
        }

        // List models endpoint - Specialized handler with fallback
        (Method::GET, ["api", "tags"]) => handle_models_endpoint(ollama_config, client_ip).await,

        // Model management endpoints with authentication
        (Method::POST, ["api", "create" | "copy" | "pull" | "push"])
        | (Method::DELETE, ["api", "delete"]) => {
            let operation = path_parts[1];
            handle_model_management_endpoint(req, ollama_config, path, operation, client_ip).await
        }

        // Default case: Forward the request directly to Ollama
        _ => forward_to_ollama(req, ollama_config, path, client_ip).await,
    }
}

// Function to handle requests that are blocked due to IP restriction
fn handle_ip_blocked(client_ip: &SocketAddr) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "application/json")
        .body(full(format!(
            r#"{{"error":"Forbidden - IP address {client_ip} is not allowed"}}"#
        )))
        .unwrap()
}

// Helper function to get the client IP, considering X-Forwarded-For header for testing
fn get_client_ip(req: &Request<hyper::body::Incoming>, socket_addr: &SocketAddr) -> SocketAddr {
    // For testing purposes, we'll check if X-Forwarded-For header is present
    if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Take the first IP in the list
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<std::net::IpAddr>() {
                    // Create a new SocketAddr with the same port but different IP
                    return SocketAddr::new(ip, socket_addr.port());
                }
            }
        }
    }

    // Default to the socket address if header parsing fails
    *socket_addr
}

// Our service handler function
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    ollama_config: std::sync::Arc<OllamaConfig>,
    socket_addr: SocketAddr,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let uri_path = req.uri().path().to_string();

    // Get the effective client IP (considering X-Forwarded-For header)
    let client_ip = get_client_ip(&req, &socket_addr);

    // Log the incoming request
    log_request(&ollama_config.logger, &method, &uri_path, &client_ip).await;

    // Check if the client IP is allowed
    if !ollama_config.is_ip_allowed(&client_ip) {
        ollama_config
            .logger
            .log(&format!(
                "Blocked request from unauthorized IP: {client_ip}"
            ))
            .await;

        // Log the response status for the blocked request
        let response = handle_ip_blocked(&client_ip);
        log_response(
            &ollama_config.logger,
            &method,
            &uri_path,
            &response.status(),
            &client_ip,
        )
        .await;

        return Ok(response);
    }

    let response = match (method.clone(), uri_path.as_str()) {
        // Forward root endpoint to Ollama
        (_, "/") => forward_to_ollama(req, &ollama_config, "/", &client_ip).await,

        // Proxy any Ollama API endpoints directly through our unified handler
        (_, path) if path.starts_with("/api/") => {
            handle_api_endpoint(req, &ollama_config, path, &client_ip).await
        }

        // Return 404 Not Found for any other request
        _ => handle_not_found(),
    };

    // Log the response status
    log_response(
        &ollama_config.logger,
        &method,
        &uri_path,
        &response.status(),
        &client_ip,
    )
    .await;

    Ok(response)
}

// Function to load TLS certificates
fn load_tls_config(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Load certificate
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let mut cert_chain = Vec::new();

    for cert_result in certs(&mut cert_reader) {
        let cert = cert_result?;
        cert_chain.push(cert);
    }

    if cert_chain.is_empty() {
        return Err("No certificates found in certificate file".into());
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut private_keys = Vec::new();

    for key_result in pkcs8_private_keys(&mut key_reader) {
        let key = key_result?;
        private_keys.push(key);
    }

    if private_keys.is_empty() {
        return Err("No private keys found in key file".into());
    }

    // Create TLS configuration with the first private key
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_keys.remove(0).into())?;

    Ok(config)
}

// Run HTTP server implementation
async fn run_http_server(
    addr: SocketAddr,
    args: Args,
    logger: Arc<Logger>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create Ollama configuration
    let ollama_config = OllamaConfig::new(
        args.ollama_url.clone(),
        logger.clone(),
        args.api_key.clone(),
        args.allowed_ips.clone(),
        args.min_keep_alive.clone(),
    );

    logger
        .log(&format!(
            "Forwarding requests to Ollama server at: {}",
            ollama_config.base_url
        ))
        .await;

    if args.api_key.is_some() {
        logger
            .log("API authentication enabled for model management endpoints")
            .await;
    } else {
        logger.log("WARNING: API authentication not configured. All endpoints are publicly accessible!").await;
    }

    if let Some(ref allowed_ips) = ollama_config.allowed_ips {
        if allowed_ips.is_empty() {
            logger
                .log("WARNING: IP allowlist is empty. All requests will be blocked!")
                .await;
        } else {
            logger
                .log(&format!(
                    "IP address allowlist enabled. Only {} IP addresses are allowed to connect.",
                    allowed_ips.len()
                ))
                .await;
            // Log the list of allowed IPs if it's not too large
            if allowed_ips.len() <= 10 {
                logger
                    .log(&format!(
                        "Allowed IPs: {}",
                        allowed_ips
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .await;
            }
        }
    }

    if let Some(ref log_path) = args.log_file {
        let rotation_msg = if args.max_log_files > 0 {
            format!(
                "Logging to file: {} (rotation at {}, keeping max {} rotated files)",
                log_path.display(),
                args.log_rotate_size,
                args.max_log_files
            )
        } else {
            format!(
                "Logging to file: {} (rotation at {}, no limit on rotated files)",
                log_path.display(),
                args.log_rotate_size
            )
        };
        logger.log(&rotation_msg).await;
    } else {
        logger.log("Logging to console only (no log file)").await;
    }

    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    logger
        .log(&format!("REST API server listening on http://{addr}"))
        .await;
    logger
        .log(&format!(
            "Root endpoint (/) forwards to Ollama server at: {}",
            ollama_config.base_url
        ))
        .await;

    log_api_endpoints(&logger).await;

    // Log minimum keep_alive setting if configured
    if let Some(min_seconds) = ollama_config.min_keep_alive_seconds {
        if min_seconds < 0 {
            logger.log("Minimum keep_alive time set to infinite").await;
        } else {
            logger
                .log(&format!(
                    "Minimum keep_alive time set to {min_seconds} seconds"
                ))
                .await;
        }
    }

    // Shared configuration for all connections
    let ollama_config = std::sync::Arc::new(ollama_config);

    // Accept connections in a loop
    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        logger.log(&format!("Connection from: {addr}")).await;
        let io = TokioIo::new(tcp_stream);

        // Clone the configuration for this connection
        let ollama_config = ollama_config.clone();
        // Save the client IP for this connection
        let client_ip = addr;

        // Spawn a new task for each connection
        tokio::task::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let config = ollama_config.clone();
                let client_addr = client_ip;
                async move { handle_request(req, config, client_addr).await }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                let err_msg = format!("Error serving connection: {err:?}");
                eprintln!("{err_msg}");
                // Cannot use logger here as it requires await which is not allowed in this context
            }
        });
    }
}

// Run HTTPS server implementation
async fn run_https_server(
    addr: SocketAddr,
    tls_config: ServerConfig,
    args: Args,
    logger: Arc<Logger>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create Ollama configuration
    let ollama_config = OllamaConfig::new(
        args.ollama_url.clone(),
        logger.clone(),
        args.api_key.clone(),
        args.allowed_ips.clone(),
        args.min_keep_alive.clone(),
    );

    logger
        .log(&format!(
            "Forwarding requests to Ollama server at: {}",
            ollama_config.base_url
        ))
        .await;

    if args.api_key.is_some() {
        logger
            .log("API authentication enabled for model management endpoints")
            .await;
    } else {
        logger.log("WARNING: API authentication not configured. All endpoints are publicly accessible!").await;
    }

    if let Some(ref allowed_ips) = ollama_config.allowed_ips {
        if allowed_ips.is_empty() {
            logger
                .log("WARNING: IP allowlist is empty. All requests will be blocked!")
                .await;
        } else {
            logger
                .log(&format!(
                    "IP address allowlist enabled. Only {} IP addresses are allowed to connect.",
                    allowed_ips.len()
                ))
                .await;
            // Log the list of allowed IPs if it's not too large
            if allowed_ips.len() <= 10 {
                logger
                    .log(&format!(
                        "Allowed IPs: {}",
                        allowed_ips
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .await;
            }
        }
    }

    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    logger
        .log(&format!("REST API server listening on https://{addr}"))
        .await;
    logger
        .log(&format!(
            "Root endpoint (/) forwards to Ollama server at: {}",
            ollama_config.base_url
        ))
        .await;

    log_api_endpoints(&logger).await;

    // Log minimum keep_alive setting if configured
    if let Some(min_seconds) = ollama_config.min_keep_alive_seconds {
        if min_seconds < 0 {
            logger.log("Minimum keep_alive time set to infinite").await;
        } else {
            logger
                .log(&format!(
                    "Minimum keep_alive time set to {min_seconds} seconds"
                ))
                .await;
        }
    }

    // Create TLS acceptor
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Shared configuration for all connections
    let ollama_config = std::sync::Arc::new(ollama_config);

    // Accept connections in a loop
    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        logger.log(&format!("Connection from: {addr}")).await;

        // Accept the TLS connection
        let tls_acceptor = tls_acceptor.clone();
        let ollama_config = ollama_config.clone();
        let logger = logger.clone();

        // Spawn a new task for each connection
        tokio::task::spawn(async move {
            match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    // Convert to TokioIo
                    let io = TokioIo::new(tls_stream);

                    // Save the client IP for this connection
                    let client_ip = addr;

                    let service = hyper::service::service_fn(move |req| {
                        let config = ollama_config.clone();
                        let client_addr = client_ip;
                        async move { handle_request(req, config, client_addr).await }
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        let err_msg = format!("Error serving TLS connection: {err:?}");
                        eprintln!("{err_msg}");
                        // Cannot use logger here as it requires await which is not allowed in this context
                    }
                }
                Err(e) => {
                    // Log TLS handshake errors
                    if let Ok(err_msg) =
                        tokio::task::spawn_blocking(move || format!("TLS handshake error: {e}"))
                            .await
                    {
                        logger.log(&err_msg).await;
                    }
                }
            }
        });
    }
}

// Helper function to log API endpoints
async fn log_api_endpoints(logger: &Logger) {
    logger.log("API endpoints:").await;
    logger
        .log("  POST /api/generate - Generate text from a model")
        .await;
    logger
        .log("  POST /api/chat - Generate the next message in a chat with a provided model")
        .await;
    logger
        .log("  POST /api/embed - Generate embeddings from a model")
        .await;
    logger
        .log("  POST /api/embeddings - Deprecated. Similar to /api/embed")
        .await;
    logger
        .log("  GET  /api/tags     - List available models")
        .await;
    logger
        .log("  POST /api/create   - Create a new model (auth required)")
        .await;
    logger
        .log("  POST /api/copy     - Copy a model (auth required)")
        .await;
    logger
        .log("  DELETE /api/delete - Delete a model (auth required)")
        .await;
    logger
        .log("  POST /api/pull     - Pull a model (auth required)")
        .await;
    logger
        .log("  POST /api/push     - Push a model (auth required)")
        .await;
    logger
        .log("  Note: To unload a model, use /api/generate with empty prompt and keep_alive: 0")
        .await;

    // If using any value format, also mention it
    logger
        .log("  Note: keep_alive supports time formats like \"30s\", \"5m\", \"1h30m\", \"3h1m5s\", \"-1s\" (infinite)")
        .await;
}

// Helper function to create detailed JSON logs for requests and responses
#[allow(clippy::too_many_arguments)]
async fn log_detailed_json(
    logger: &Logger,
    direction: &str,
    method: &Method,
    path: &str,
    status: Option<StatusCode>,
    body_bytes: &Bytes,
    client_ip: &SocketAddr,
    headers: &hyper::HeaderMap<hyper::header::HeaderValue>,
) {
    // Try to parse the body as JSON for prettier logging
    let body_str = String::from_utf8_lossy(body_bytes);
    let body_json = if body_bytes.is_empty() {
        serde_json::json!({ "content": "<empty>" })
    } else if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body_str) {
        value
    } else {
        // If not valid JSON, create a JSON string with the content
        serde_json::json!({ "content": body_str })
    };

    let status_code = status.map_or(0, |s| s.as_u16());

    // Convert headers to a map of string -> string
    let headers_json = headers.iter().map(|(k, v)| {
        let key = k.as_str().to_string();
        let value = v.to_str().unwrap_or("").to_string();
        (key, value)
    }).collect::<std::collections::BTreeMap<_, _>>();

    // Create the detailed log entry
    let log_entry = serde_json::json!({
        "timestamp": Local::now().to_rfc3339(),
        "direction": direction,
        "client_ip": client_ip.to_string(),
        "method": method.to_string(),
        "path": path,
        "status": status_code,
        "headers": headers_json,
        "body": body_json
    });

    // Log the JSON entry
    if let Ok(log_json) = serde_json::to_string_pretty(&log_entry) {
        logger.log(&format!("DETAILED JSON LOG: {log_json}")).await;
    } else {
        logger.log("Failed to serialize detailed log to JSON").await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args = Args::parse();

    // Parse the host address into an IP address
    let ip = match args.host.parse::<std::net::IpAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!(
                "Error parsing host address: {e}. Please provide a valid IP address."
            );
            return Err(format!("Invalid host address: {}", args.host).into());
        }
    };

    // Set up the server address
    let addr = SocketAddr::new(ip, args.port);

    // Create logger
    let logger = Arc::new(
        Logger::new(
            args.log_file.clone(),
            args.log_rotate_size.clone(),
            args.max_log_files,
        )
        .await,
    );

    // Log startup configuration information
    logger.log("Ollama Proxy Server starting up").await;
    logger.log("Arguments can be provided via command line or environment variables with prefix PROXY_OLLAMA_").await;

    // Check HTTPS configuration
    if args.https {
        // Validate certificate and key files
        if args.cert_file.is_none() || args.key_file.is_none() {
            eprintln!("Error: HTTPS mode requires both --cert-file and --key-file parameters");
            eprintln!("\nExample usage:");
            eprintln!(
                "  cargo run -- --https --cert-file path/to/cert.pem --key-file path/to/key.pem"
            );
            eprintln!(
                "\nYou can generate a self-signed certificate for testing using the provided script:"
            );
            eprintln!("  ./generate_cert.sh");
            return Err("HTTPS mode requires both --cert-file and --key-file parameters".into());
        }

        let cert_file = args.cert_file.as_ref().unwrap();
        let key_file = args.key_file.as_ref().unwrap();

        // Load TLS configuration
        let tls_config = match load_tls_config(cert_file, key_file) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading TLS configuration: {e}");
                return Err(format!("Failed to load TLS configuration: {e}").into());
            }
        };

        logger.log("HTTPS mode enabled").await;
        logger
            .log(&format!("Using certificate file: {}", cert_file.display()))
            .await;
        logger
            .log(&format!("Using private key file: {}", key_file.display()))
            .await;

        // Run the server in HTTPS mode
        run_https_server(addr, tls_config, args, logger).await?;
    } else {
        // Run the server in HTTP mode
        logger.log("HTTP mode enabled (no encryption)").await;
        if args.host == "0.0.0.0" {
            logger
                .log("WARNING: Server is listening on all network interfaces without encryption")
                .await;
        }

        run_http_server(addr, args, logger).await?;
    }

    Ok(())
}
