# Ollama API Proxy Server

This is a lightweight HTTP server that acts as a proxy for the Ollama API. It forwards requests to an Ollama server and provides additional features like API authentication, IP allowlisting, and HTTPS support.

## Features

- **API Forwarding:** Forwards requests to an Ollama API server
- **Authentication:** Optional API key authentication for model management endpoints
- **IP Allowlisting:** Restrict access to specific IP addresses
- **HTTPS Support:** Optional TLS/SSL encryption for secure connections
- **Logging:** Console and file logging options

## Usage

### Basic HTTP Server

```bash
cargo run -- --port 3001 --ollama-url http://localhost:11434
```

### With Authentication

```bash
cargo run -- --port 3001 --ollama-url http://localhost:11434 --api-key YOUR_SECRET_KEY
```

### With IP Allowlisting

```bash
cargo run -- --port 3001 --ollama-url http://localhost:11434 --allowed-ips "127.0.0.1,192.168.1.5"
```

### With HTTPS (Secure Connections)

First, generate a self-signed certificate for testing:

```bash
./generate_cert.sh
```

Then run the server with HTTPS enabled:

```bash
cargo run -- --https --cert-file ./certs/server.crt --key-file ./certs/server.key
```

To make the server publicly accessible on all network interfaces:

```bash
cargo run -- --https --cert-file ./certs/server.crt --key-file ./certs/server.key --host 0.0.0.0
```

### Using Environment Variables

All command-line arguments can also be specified using environment variables with the `PROXY_OLLAMA_` prefix. For example:

```bash
export PROXY_OLLAMA_PORT=3001
export PROXY_OLLAMA_URL="http://localhost:11434"
export PROXY_OLLAMA_API_KEY="your-secret-key"
export PROXY_OLLAMA_ALLOWED_IPS="127.0.0.1,192.168.1.5"
export PROXY_OLLAMA_HTTPS=true
export PROXY_OLLAMA_CERT_FILE="./certs/server.crt"
export PROXY_OLLAMA_KEY_FILE="./certs/server.key"
export PROXY_OLLAMA_HOST="0.0.0.0"
export PROXY_OLLAMA_LOG_FILE="./proxy.log"
export PROXY_OLLAMA_LOG_ROTATE_SIZE="10MB"
export PROXY_OLLAMA_MAX_LOG_FILES=5

cargo run
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--port` | Port to listen on (default: 3001) |
| `--ollama-url` | Ollama server URL (default: http://localhost:11434) |
| `--log-file` | Output log file (if not specified, logs go to stdout only) |
| `--api-key` | API key required for model management endpoints |
| `--allowed-ips` | List of allowed IP addresses (comma-separated) |
| `--https` | Enable HTTPS mode |
| `--cert-file` | TLS certificate file path (required when HTTPS is enabled) |
| `--key-file` | TLS private key file path (required when HTTPS is enabled) |
| `--host` | Host address to listen on (default: 127.0.0.1, use 0.0.0.0 to listen on all interfaces) |
| `--log-rotate-size` | Maximum log file size before rotation (default: 10MB) |
| `--max-log-files` | Maximum number of rotated log files to keep (default: 0, unlimited) |

## API Endpoints

Documentation for all API endpoints is available at the root URL (e.g., `http://localhost:3001/` or `https://localhost:3001/`).

## Testing HTTPS

To quickly test the HTTPS functionality, use the provided demo script:

```bash
./demo_https.sh
```

This script will:

1. Generate self-signed certificates if they don't exist
2. Build the server
3. Start the server with HTTPS enabled
4. Test the connection using curl
5. Show instructions for further testing

You can also manually test the HTTPS connection using the included test script:

```bash
./test_https.sh -p 3001 -v  # -v for verbose output
```

For production use, replace the self-signed certificate with a proper SSL certificate from a trusted certificate authority.
