// filepath: /home/main/src/http_server/src/main.rs
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

    // Build a client

    // Build the full URI
    let uri = match ollama_config.build_uri(path) {
        Ok(uri) => uri,
        Err(e) => {
            let err_msg = format!("Error parsing URI for path {path}: {e}");
            ollama_config.logger.log(&err_msg).await;
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full("Invalid URI"))
                .unwrap());
        }
    };

    // Create client
    let client = Client::builder(TokioExecutor::new()).build_http();

    // Build request to forward
    let mut request_builder = Request::builder().uri(uri).method(parts.method);

    // Copy headers - use direct access to headers
    if let Some(headers) = request_builder.headers_mut() {
        for (name, value) in parts.headers {
            if let Some(header_name) = name {
                headers.insert(header_name, value);
            }
        }
    }

    // Add body if it exists
    let forwarded_req = if let Some(body_bytes) = maybe_body_bytes {
        request_builder.body(Full::new(body_bytes).boxed()).unwrap()
    } else {
        request_builder
            .body(Full::new(Bytes::new()).boxed())
            .unwrap()
    }; // Send to Ollama
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
                        for (name, value) in parts.headers {
                            // Only insert if name is valid
                            if let Some(header_name) = name {
                                headers.insert(header_name, value);
                            }
                        }
                    }

                    Ok(builder.body(full(bytes)).unwrap())
                }
                Err(e) => {
                    let err_msg = format!("Error collecting Ollama response body: {e}");
                    ollama_config.logger.log(&err_msg).await;
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(full("Error collecting response from Ollama"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Error forwarding request to Ollama: {e}");
            ollama_config.logger.log(&err_msg).await;
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("Error forwarding request to Ollama: {e}")))
                .unwrap())
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
            if let Some(model) = json.get("model").and_then(|m| m.as_str()) {
                let is_unload_request = json
                    .get("prompt")
                    .and_then(|p| p.as_str())
                    .is_some_and(str::is_empty)
                    && (json
                        .get("options")
                        .and_then(|o| o.as_object())
                        .and_then(|o| o.get("keep_alive"))
                        .and_then(serde_json::Value::as_i64)
                        == Some(0));

                if is_unload_request {
                    ollama_config
                        .logger
                        .log(&format!("Unloading model from memory: {model}"))
                        .await;
                } else {
                    ollama_config
                        .logger
                        .log(&format!(
                            "Forwarding generate request to Ollama for model: {model}"
                        ))
                        .await;
                }
            }
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
    // Forward the request directly to Ollama
    if let Ok(response) = proxy_to_ollama(req, "/api/generate", ollama_config).await {
        response
    } else {
        // Fallback to mock response if Ollama is unavailable
        ollama_config
            .logger
            .log("Failed to get response from Ollama, using mock response")
            .await;
        let response = serde_json::json!({
            "model": "unknown",
            "created_at": Local::now().to_rfc3339(),
            "response": "Mock response (Ollama server unavailable)",
            "done": true
        });
        json_response(&response, StatusCode::OK)
    }
}

// Simplified handler for the generate endpoint that delegates to the specialized handler
async fn handle_generate_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_generate_with_model_info(req, ollama_config).await
}

// Handle the /api/tags endpoint - Forward AS-IS to Ollama
async fn handle_tags_endpoint(ollama_config: &Arc<OllamaConfig>) -> Response<BoxBody> {
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

// Handle the documentation endpoint
fn handle_docs_endpoint() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(full(
            "<html><body><h1>API Documentation</h1>
            <p>This server implements an Ollama-like API, forwarding requests to an Ollama server</p>
            <h2>Endpoints:</h2>
            <ul>
                <li><code>POST /api/generate</code> - Generate text from a model</li>
                <li><code>GET /api/tags</code> - List available models</li>
                <li><code>POST /api/create</code> - Create a new model (requires authentication)</li>
                <li><code>POST /api/copy</code> - Copy a model (requires authentication)</li>
                <li><code>DELETE /api/delete</code> - Delete a model (requires authentication)</li>
                <li><code>POST /api/pull</code> - Pull a model (requires authentication)</li>
                <li><code>POST /api/push</code> - Push a model (requires authentication)</li>
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

// Generic handler for Ollama API endpoints that require authentication
async fn handle_authenticated_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
    path: &str,
    operation_description: &str,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config) {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log(&format!(
            "Forwarding {operation_description} request to Ollama"
        ))
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, path, ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {e}")))
                .unwrap()
        })
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
    // Forward the request directly to Ollama
    if let Ok(response) = proxy_to_ollama(req, path, ollama_config).await {
        response
    } else {
        // Fallback to mock response if Ollama is unavailable
        ollama_config
            .logger
            .log("Failed to get response from Ollama, using fallback response")
            .await;
        fallback_generator()
    }
}

// Handle model creation endpoint - Forward AS-IS to Ollama
async fn handle_create_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_authenticated_endpoint(req, ollama_config, "/api/create", "model create").await
}

// Handle model copy endpoint - Forward AS-IS to Ollama
async fn handle_copy_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_authenticated_endpoint(req, ollama_config, "/api/copy", "model copy").await
}

// Handle model delete endpoint - Forward AS-IS to Ollama
async fn handle_delete_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_authenticated_endpoint(req, ollama_config, "/api/delete", "model delete").await
}

// Handle model pull endpoint - Forward AS-IS to Ollama
async fn handle_pull_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_authenticated_endpoint(req, ollama_config, "/api/pull", "model pull").await
}

// Handle model push endpoint - Forward AS-IS to Ollama
async fn handle_push_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    handle_authenticated_endpoint(req, ollama_config, "/api/push", "model push").await
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
        // API Endpoints

        // Generate endpoint - Forward to Ollama
        (Method::POST, "/api/generate") => handle_generate_endpoint(req, &ollama_config).await,

        // List models endpoint - Forward to Ollama
        (Method::GET, "/api/tags") => handle_tags_endpoint(&ollama_config).await,

        // Model management endpoints with authentication
        (Method::POST, "/api/create") => handle_create_model_endpoint(req, &ollama_config).await,
        (Method::POST, "/api/copy") => handle_copy_model_endpoint(req, &ollama_config).await,
        (Method::DELETE, "/api/delete") => handle_delete_model_endpoint(req, &ollama_config).await,
        (Method::POST, "/api/pull") => handle_pull_model_endpoint(req, &ollama_config).await,
        (Method::POST, "/api/push") => handle_push_model_endpoint(req, &ollama_config).await,

        // API documentation
        (Method::GET, "/") => handle_docs_endpoint(),

        // Proxy any other Ollama API endpoints directly
        (_, path) if path.starts_with("/api/") => {
            proxy_to_ollama(req, path, &ollama_config).await?
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
