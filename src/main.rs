// This will be our simplified main.rs file without the unused functions

use bytes::Bytes;
use chrono::Local;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, Sender};

// OpenAI API compatibility module
mod openai;

// A simple type alias for convenience
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// Command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3001)]
    port: u16,

    /// Ollama server URL
    #[arg(short, long, default_value = "http://localhost:11434")]
    ollama_url: String,

    /// Output log file (if not specified, logs go to stdout only)
    #[arg(short, long)]
    log_file: Option<PathBuf>,

    /// API key required for model management endpoints (create, copy, delete, pull, push)
    #[arg(short, long)]
    api_key: Option<String>,
}

// Logger that can write to both console and file
struct Logger {
    log_sender: Sender<String>,
}

impl Logger {
    async fn new(log_path: Option<PathBuf>) -> Self {
        // Create a channel for logging messages
        let (log_sender, mut log_receiver) = mpsc::channel::<String>(100);

        // Open log file if path provided
        let log_file = if let Some(path) = log_path {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(file) => Some(file),
                Err(e) => {
                    eprintln!("Error opening log file: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Spawn a background task to handle log messages
        tokio::spawn(async move {
            let mut file = log_file;

            while let Some(message) = log_receiver.recv().await {
                // Always print to console
                println!("{message}");

                // Also log to file if configured
                if let Some(ref mut f) = file {
                    let message_with_newline = format!("{message}\n");
                    // Ignore error if we can't write to the file
                    if let Err(e) = f.write_all(message_with_newline.as_bytes()).await {
                        eprintln!("Error writing to log file: {e}");
                    }
                    // Try to flush, but ignore errors
                    let _ = f.flush().await;
                }
            }
        });

        Self { log_sender }
    }

    async fn log(&self, message: &str) {
        // Send message to the logger task
        // If send fails, just print to stderr and continue
        if let Err(e) = self.log_sender.send(message.to_string()).await {
            eprintln!("Failed to send log message: {e}");
            // Fallback to direct console output
            println!("{message}");
        }
    }
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
}

impl OllamaConfig {
    fn new(base_url: String, logger: Arc<Logger>, api_key: Option<String>) -> Self {
        Self {
            base_url,
            logger,
            api_key,
        }
    }

    // Build a full URI for an Ollama API endpoint
    fn build_uri(&self, path: &str) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        let uri_str = format!("{}{}", self.base_url, path);
        uri_str.parse::<hyper::Uri>()
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
async fn build_ollama_uri(
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
        target.insert(name.clone(), value.clone());
    }
}

// Proxy an API request to Ollama
async fn proxy_to_ollama<B>(
    req: Request<B>,
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
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
        Ok(collected) => Some(collected.to_bytes()),
        Err(e) => {
            let err_msg = format!("Error collecting request body: {e:?}");
            ollama_config.logger.log(&err_msg).await;
            None
        }
    };

    // Build the full URI
    let uri = match build_ollama_uri(path, ollama_config).await {
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
async fn log_request(logger: &Logger, method: &Method, path: &str) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger.log(&format!("[{now}] {method} {path}")).await;
}

// Helper function to log responses
async fn log_response(logger: &Logger, method: &Method, path: &str, status: &StatusCode) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger
        .log(&format!("[{now}] {method} {path} - {}", status.as_u16()))
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
    json.get("prompt")
        .and_then(|p| p.as_str())
        .is_some_and(str::is_empty)
        && (json
            .get("options")
            .and_then(|o| o.as_object())
            .and_then(|o| o.get("keep_alive"))
            .and_then(serde_json::Value::as_i64)
            == Some(0))
}

// Extract and log model information from generate request
async fn log_model_info(
    json: &serde_json::Value,
    logger: &Logger,
) {
    if let Some(model) = json.get("model").and_then(|m| m.as_str()) {
        let is_unload_request = is_unload_model_request(json);

        if is_unload_request {
            logger
                .log(&format!("Unloading model from memory: {model}"))
                .await;
        } else {
            logger
                .log(&format!(
                    "Forwarding generate request to Ollama for model: {model}"
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
) -> Response<BoxBody> {
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

    // If we have the body bytes, try to log helpful information
    if let Some(ref body_bytes) = maybe_body_bytes {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
            log_model_info(&json, &ollama_config.logger).await;
        }
    }

    // Create a new request with the body we read for Ollama
    let uri = ollama_config
        .build_uri("/api/generate")
        .expect("Failed to build URI for generate endpoint");

    let req = Request::builder()
        .uri(uri)
        .method(Method::POST)
        .body(
            Full::new(if let Some(bytes) = maybe_body_bytes {
                bytes
            } else {
                Bytes::new()
            })
            .boxed(),
        )
        .expect("Failed to create request");

    // Forward the request directly to Ollama
    match proxy_to_ollama(req, "/api/generate", ollama_config).await {
        Ok(response) => response,
        Err(_) => {
            // Fallback to mock response if Ollama is unavailable
            ollama_config
                .logger
                .log("Failed to get response from Ollama, using mock response")
                .await;
            create_generate_fallback_response()
        }
    }
}

// Handle the documentation endpoint
fn handle_docs_endpoint() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(full(
            "<html><body><h1>API Documentation</h1>
            <p>This server implements an Ollama-like API, forwarding requests to an Ollama server</p>
            <h2>Ollama Native Endpoints:</h2>
            <ul>
                <li><code>POST /api/generate</code> - Generate text from a model</li>
                <li><code>GET /api/tags</code> - List available models</li>
                <li><code>POST /api/create</code> - Create a new model (requires authentication)</li>
                <li><code>POST /api/copy</code> - Copy a model (requires authentication)</li>
                <li><code>DELETE /api/delete</code> - Delete a model (requires authentication)</li>
                <li><code>POST /api/pull</code> - Pull a model (requires authentication)</li>
                <li><code>POST /api/push</code> - Push a model (requires authentication)</li>
            </ul>
            <h2>OpenAI-Compatible Endpoints:</h2>
            <ul>
                <li><code>POST /v1/chat/completions</code> - Chat with a model (OpenAI compatible)</li>
                <li><code>POST /v1/completions</code> - Generate text (OpenAI compatible)</li>
                <li><code>POST /v1/embeddings</code> - Generate embeddings (OpenAI compatible)</li>
                <li><code>GET /v1/models</code> - List available models (OpenAI compatible)</li>
                <li><code>GET /v1/models/{model}</code> - Get model info (OpenAI compatible)</li>
            </ul>
            <h2>Special Operations:</h2>
            <ul>
                <li><strong>Unload a model:</strong> To unload a model from memory, send a request to <code>POST /api/generate</code> with an empty prompt and <code>keep_alive: 0</code> in the options. Example:
                <pre>{
  \"model\": \"MODEL_NAME\",
  \"prompt\": \"\",
  \"options\": {
    \"keep_alive\": 0
  }
}</pre>
                </li>
            </ul>
            <h2>Authentication:</h2>
            <p>For model management endpoints (create, copy, delete, pull, push), an API key is required.
            Pass the API key in the Authorization header as:<br/>
            <code>Authorization: Bearer YOUR_API_KEY</code></p>
            </body></html>"
        ))
        .unwrap()
}

// Generic handler for Ollama API endpoints with fallback responses
async fn handle_ollama_endpoint_with_fallback<F>(
    method: Method,
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
    log_message: &str,
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
    match proxy_to_ollama(req, path, ollama_config).await {
        Ok(response) => response,
        Err(_) => {
            // Fallback to mock response if Ollama is unavailable
            ollama_config
                .logger
                .log("Failed to get response from Ollama, using fallback response")
                .await;
            fallback_generator()
        }
    }
}

// Function to handle proxy errors consistently
fn handle_proxy_error(e: hyper::Error) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(full(format!("Error: {e}")))
        .unwrap()
}

// Handle model listing endpoint with fallback
async fn handle_models_endpoint(ollama_config: &Arc<OllamaConfig>) -> Response<BoxBody> {
    handle_ollama_endpoint_with_fallback(
        Method::GET,
        "/api/tags",
        ollama_config,
        "Forwarding request to list models to Ollama",
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
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config) {
        return handle_unauthorized();
    }

    // Log the operation
    let operation_description = format!("model {operation}");
    ollama_config
        .logger
        .log(&format!(
            "Forwarding {operation_description} request to Ollama"
        ))
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, path, ollama_config)
        .await
        .unwrap_or_else(handle_proxy_error)
}

// Forward any API request to Ollama (default handler)
async fn forward_to_ollama(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
) -> Response<BoxBody> {
    ollama_config
        .logger
        .log(&format!("Forwarding request to Ollama: {path}"))
        .await;

    proxy_to_ollama(req, path, ollama_config)
        .await
        .unwrap_or_else(handle_proxy_error)
}

// Handle API endpoints based on their route pattern
// This unified function routes requests to appropriate specialized handlers
async fn handle_api_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
) -> Response<BoxBody> {
    // Extract method and path components for routing
    let method = req.method().clone();
    let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (method, path_parts.as_slice()) {
        // Generate endpoint - Forward with model info handling
        (Method::POST, ["api", "generate"]) => {
            handle_generate_with_model_info(req, ollama_config).await
        }

        // List models endpoint - Specialized handler with fallback
        (Method::GET, ["api", "tags"]) => handle_models_endpoint(ollama_config).await,

        // Model management endpoints with authentication
        (Method::POST, ["api", "create"])
        | (Method::POST, ["api", "copy"])
        | (Method::POST, ["api", "pull"])
        | (Method::POST, ["api", "push"])
        | (Method::DELETE, ["api", "delete"]) => {
            let operation = path_parts[1];
            handle_model_management_endpoint(req, ollama_config, path, operation).await
        }

        // Default case: Forward the request directly to Ollama
        _ => forward_to_ollama(req, ollama_config, path).await,
    }
}

// Our service handler function
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    ollama_config: std::sync::Arc<OllamaConfig>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let uri_path = req.uri().path().to_string();

    // Log the incoming request
    log_request(&ollama_config.logger, &method, &uri_path).await;

    let response = match (method.clone(), uri_path.as_str()) {
        // API documentation
        (Method::GET, "/") => handle_docs_endpoint(),

        // Proxy any Ollama API endpoints directly through our unified handler
        (_, path) if path.starts_with("/api/") => {
            handle_api_endpoint(req, &ollama_config, path).await
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
    )
    .await;

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args = Args::parse();

    // Set up the server address
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));

    // Create logger
    let logger = Arc::new(Logger::new(args.log_file.clone()).await);

    // Create Ollama configuration
    let ollama_config = OllamaConfig::new(
        args.ollama_url.clone(),
        logger.clone(),
        args.api_key.clone(),
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

    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    logger
        .log(&format!("REST API server listening on http://{addr}"))
        .await;
    logger
        .log(&format!(
            "Documentation available at http://127.0.0.1:{}/",
            args.port
        ))
        .await;
    logger.log("API endpoints:").await;
    logger
        .log("  POST /api/generate - Generate text from a model")
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

    // Shared configuration for all connections
    let ollama_config = std::sync::Arc::new(ollama_config);

    // Accept connections in a loop
    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        logger.log(&format!("Connection from: {addr}")).await;
        let io = TokioIo::new(tcp_stream);

        // Clone the configuration for this connection
        let ollama_config = ollama_config.clone();

        // Spawn a new task for each connection
        tokio::task::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let config = ollama_config.clone();
                async move { handle_request(req, config).await }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                let err_msg = format!("Error serving connection: {err:?}");
                eprintln!("{err_msg}");
                // Cannot use logger here as it requires await which is not allowed in this context
            }
        });
    }
}
