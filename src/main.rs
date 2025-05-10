// filepath: /home/main/src/http_server/src/main.rs
use bytes::Bytes;
use chrono::Local;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

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
    log_file: Option<Mutex<File>>,
}

impl Logger {
    async fn new(log_path: Option<PathBuf>) -> Self {
        let log_file = if let Some(path) = log_path {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(file) => Some(Mutex::new(file)),
                Err(e) => {
                    eprintln!("Error opening log file: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self { log_file }
    }

    async fn log(&self, message: &str) {
        // Always print to console
        println!("{}", message);

        // Also log to file if configured
        if let Some(file_mutex) = &self.log_file {
            let message = format!("{}\n", message);
            let mut file = file_mutex.lock().await;
            // Ignore error if we can't write to the file
            let _ = file.write_all(message.as_bytes()).await;
            let _ = file.flush().await;
        }
    }
}

// API Models for Ollama-like interface
#[derive(Serialize, Deserialize, Debug)]
struct GenerateRequest {
    model: String,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GenerateResponse {
    model: String,
    created_at: String,
    response: String,
    done: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ModelsResponse {
    models: Vec<ModelInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ModelInfo {
    name: String,
    modified_at: String,
    size: u64,
    digest: String,
    details: ModelDetails,
}

#[derive(Serialize, Deserialize, Debug)]
struct ModelDetails {
    format: String,
    family: String,
    parameter_size: String,
    quantization_level: String,
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

// Parse request body as JSON
async fn parse_body<T: for<'de> Deserialize<'de>>(body: hyper::body::Incoming) -> Option<T> {
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            match serde_json::from_slice::<T>(&bytes) {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    eprintln!("Error parsing request body: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Error collecting request body: {}", e);
            None
        }
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
}

// Client for forwarding requests to Ollama
async fn forward_to_ollama<T: Serialize, R: for<'de> Deserialize<'de>>(
    config: &OllamaConfig,
    endpoint: &str,
    body: Option<&T>,
) -> Option<R> {
    use http_body_util::Full;
    use hyper::Uri;
    use hyper::body::Bytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::str::FromStr;

    // Build the full URI
    let uri_str = format!("{}{}", config.base_url, endpoint);
    let uri = match Uri::from_str(&uri_str) {
        Ok(uri) => uri,
        Err(e) => {
            let err_msg = format!("Error parsing URI {}: {}", uri_str, e);
            config.logger.log(&err_msg).await;
            return None;
        }
    };

    // Create a regular HTTP client
    let client = Client::builder(TokioExecutor::new()).build_http();

    // Build request
    let mut req_builder = Request::builder().uri(uri);

    // Add JSON body if provided
    let req = if let Some(data) = body {
        match serde_json::to_string(data) {
            Ok(json) => {
                req_builder = req_builder
                    .method(Method::POST)
                    .header("Content-Type", "application/json");

                match req_builder.body(Full::new(Bytes::from(json)).boxed()) {
                    Ok(request) => request,
                    Err(e) => {
                        let err_msg = format!("Error creating request with body: {}", e);
                        config.logger.log(&err_msg).await;
                        return None;
                    }
                }
            }
            Err(e) => {
                let err_msg = format!("Error serializing request body: {}", e);
                config.logger.log(&err_msg).await;
                return None;
            }
        }
    } else {
        // GET request with no body
        match req_builder
            .method(Method::GET)
            .body(Full::<Bytes>::new(Bytes::new()).boxed())
        {
            Ok(request) => request,
            Err(e) => {
                let err_msg = format!("Error creating GET request: {}", e);
                config.logger.log(&err_msg).await;
                return None;
            }
        }
    };

    // Send the request
    let res = match client.request(req).await {
        Ok(res) => res,
        Err(e) => {
            let err_msg = format!("Error sending request to Ollama: {}", e);
            config.logger.log(&err_msg).await;
            return None;
        }
    };

    // Check if successful
    if !res.status().is_success() {
        let err_msg = format!("Ollama API returned error status: {}", res.status());
        config.logger.log(&err_msg).await;
        return None;
    }

    // Parse response body
    match BodyExt::collect(res.into_body()).await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            match serde_json::from_slice::<R>(&bytes) {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    let err_msg = format!("Error parsing Ollama response: {}", e);
                    config.logger.log(&err_msg).await;
                    None
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Error collecting Ollama response body: {}", e);
            config.logger.log(&err_msg).await;
            None
        }
    }
}

// Handle the /api/generate endpoint
async fn handle_generate_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    if let Some(generate_req) = parse_body::<GenerateRequest>(req.into_body()).await {
        // Check if this is a model unload request (empty prompt with keep_alive: 0)
        let is_unload_request = generate_req.prompt.is_empty()
            && generate_req.options.as_ref().map_or(false, |opts| {
                opts.get("keep_alive")
                    .map_or(false, |val| val.as_i64().map_or(false, |num| num == 0))
            });

        // Log appropriate message based on request type
        if is_unload_request {
            ollama_config
                .logger
                .log(&format!(
                    "Unloading model from memory: {}",
                    generate_req.model
                ))
                .await;
        } else {
            ollama_config
                .logger
                .log(&format!(
                    "Forwarding generate request to Ollama for model: {}",
                    generate_req.model
                ))
                .await;
        }

        // Forward to Ollama server
        match forward_to_ollama::<GenerateRequest, GenerateResponse>(
            ollama_config,
            "/api/generate",
            Some(&generate_req),
        )
        .await
        {
            Some(ollama_response) => json_response(&ollama_response, StatusCode::OK),
            None => {
                // Fallback to mock response if Ollama is unavailable
                ollama_config
                    .logger
                    .log("Failed to get response from Ollama, using mock response")
                    .await;
                let response = GenerateResponse {
                    model: generate_req.model,
                    created_at: Local::now().to_rfc3339(),
                    response: format!(
                        "Mock response to: {} (Ollama server unavailable)",
                        generate_req.prompt
                    ),
                    done: true,
                };
                json_response(&response, StatusCode::OK)
            }
        }
    } else {
        json_response(
            &serde_json::json!({"error": "Invalid request format"}),
            StatusCode::BAD_REQUEST,
        )
    }
}

// Handle the /api/tags endpoint
async fn handle_tags_endpoint(ollama_config: &Arc<OllamaConfig>) -> Response<BoxBody> {
    ollama_config
        .logger
        .log("Forwarding request to list models to Ollama")
        .await;

    // Forward to Ollama server
    match forward_to_ollama::<(), ModelsResponse>(ollama_config, "/api/tags", None).await {
        Some(ollama_response) => json_response(&ollama_response, StatusCode::OK),
        None => {
            // Fallback to mock response if Ollama is unavailable
            ollama_config
                .logger
                .log("Failed to get response from Ollama, using mock response")
                .await;
            // Simulate a list of models
            let models = ModelsResponse {
                models: vec![
                    ModelInfo {
                        name: "llama2".to_string(),
                        modified_at: "2023-08-02T17:02:23Z".to_string(),
                        size: 3791730298,
                        digest: "sha256:a2...".to_string(),
                        details: ModelDetails {
                            format: "gguf".to_string(),
                            family: "llama".to_string(),
                            parameter_size: "7B".to_string(),
                            quantization_level: "Q4_0".to_string(),
                        },
                    },
                    ModelInfo {
                        name: "mistral".to_string(),
                        modified_at: "2023-11-20T12:15:30Z".to_string(),
                        size: 4356823129,
                        digest: "sha256:b1...".to_string(),
                        details: ModelDetails {
                            format: "gguf".to_string(),
                            family: "mistral".to_string(),
                            parameter_size: "7B".to_string(),
                            quantization_level: "Q5_K".to_string(),
                        },
                    },
                ],
            };
            json_response(&models, StatusCode::OK)
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

// Proxy an API request to Ollama
async fn proxy_to_ollama(
    req: Request<hyper::body::Incoming>,
    path: &str,
    ollama_config: &Arc<OllamaConfig>,
) -> Result<Response<BoxBody>, hyper::Error> {
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
            let err_msg = format!("Error collecting request body: {}", e);
            ollama_config.logger.log(&err_msg).await;
            None
        }
    };

    // Build a client
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    // Build the full URI
    let uri_str = format!("{}{}", ollama_config.base_url, path);
    let uri = match uri_str.parse::<hyper::Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            let err_msg = format!("Error parsing URI {}: {}", uri_str, e);
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
                    let err_msg = format!("Error collecting Ollama response body: {}", e);
                    ollama_config.logger.log(&err_msg).await;
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(full("Error collecting response from Ollama"))
                        .unwrap())
                }
            }
        }
        Err(e) => {
            let err_msg = format!("Error forwarding request to Ollama: {}", e);
            ollama_config.logger.log(&err_msg).await;
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("Error forwarding request to Ollama: {}", e)))
                .unwrap())
        }
    }
}

// Helper function to log incoming requests
async fn log_request(logger: &Logger, method: &Method, path: &str) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger.log(&format!("[{}] {} {}", now, method, path)).await;
}

// Helper function to log responses
async fn log_response(logger: &Logger, method: &Method, path: &str, status: &StatusCode) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    logger
        .log(&format!(
            "[{}] {} {} - {}",
            now,
            method,
            path,
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
async fn is_authenticated(
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

// Handle model creation endpoint
async fn handle_create_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config).await {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log("Forwarding model create request to Ollama")
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, "/api/create", ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {}", e)))
                .unwrap()
        })
}

// Handle model copy endpoint
async fn handle_copy_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config).await {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log("Forwarding model copy request to Ollama")
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, "/api/copy", ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {}", e)))
                .unwrap()
        })
}

// Handle model delete endpoint
async fn handle_delete_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config).await {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log("Forwarding model delete request to Ollama")
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, "/api/delete", ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {}", e)))
                .unwrap()
        })
}

// Handle model pull endpoint
async fn handle_pull_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config).await {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log("Forwarding model pull request to Ollama")
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, "/api/pull", ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {}", e)))
                .unwrap()
        })
}

// Handle model push endpoint
async fn handle_push_model_endpoint(
    req: Request<hyper::body::Incoming>,
    ollama_config: &Arc<OllamaConfig>,
) -> Response<BoxBody> {
    // Check authentication
    if !is_authenticated(&req, ollama_config).await {
        return handle_unauthorized();
    }

    ollama_config
        .logger
        .log("Forwarding model push request to Ollama")
        .await;

    // Forward to Ollama server
    proxy_to_ollama(req, "/api/push", ollama_config)
        .await
        .unwrap_or_else(|e| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(full(format!("Error: {}", e)))
                .unwrap()
        })
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

    if let Some(_) = &args.api_key {
        logger
            .log("API authentication enabled for model management endpoints")
            .await;
    } else {
        logger.log("WARNING: API authentication not configured. All endpoints are publicly accessible!").await;
    }

    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    logger
        .log(&format!("REST API server listening on http://{}", addr))
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
        logger.log(&format!("Connection from: {}", addr)).await;
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
                let err_msg = format!("Error serving connection: {:?}", err);
                eprintln!("{}", err_msg);
                // Cannot use logger here as it requires await which is not allowed in this context
            }
        });
    }
}
