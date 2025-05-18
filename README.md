# Ollama API Proxy Server

[![Rust CI](https://github.com/hehaoqian/ollama-proxy/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/hehaoqian/ollama-proxy/actions/workflows/rust-ci.yml)
[![Security Audit](https://github.com/hehaoqian/ollama-proxy/actions/workflows/security-audit.yml/badge.svg)](https://github.com/hehaoqian/ollama-proxy/actions/workflows/security-audit.yml)
[![Cross-Platform Tests](https://github.com/hehaoqian/ollama-proxy/actions/workflows/cross-platform.yml/badge.svg)](https://github.com/hehaoqian/ollama-proxy/actions/workflows/cross-platform.yml)

This is a lightweight HTTP server that acts as a proxy for the Ollama API. It forwards requests to an Ollama server and provides additional features like API authentication, IP allowlisting, and HTTPS support.

## Continuous Integration

This project uses GitHub Actions for continuous integration:

- **Rust CI**: Runs `cargo fmt`, `cargo clippy`, `cargo doc`, and `cargo test` on every push and pull request
- **Security Audit**: Runs `cargo audit` to check for vulnerabilities in dependencies
- **Cross-Platform Tests**: Ensures the application works on Windows, macOS, and Linux
- **Scheduled Checks**: Weekly verification with the latest Rust toolchain

All checks treat warnings as errors to maintain high code quality.

### Running CI Locally

You can run the same CI checks locally using the provided script:

```bash
./run-ci.sh
```

This script will:

1. Check for required tools and install them if needed
2. Run `cargo fmt` to verify code formatting
3. Run `cargo clippy` with warnings treated as errors
4. Build documentation with `cargo doc` and check for documentation warnings
5. Run all tests with `cargo test`

The script will exit with an error if any of the checks fail, making it easy to catch issues before pushing to GitHub.

#### Options

The CI script supports several command-line options:

```bash
Usage: ./run-ci.sh [options]
Options:
  -h, --help             Show this help message
  -f, --format-only      Run only formatting checks
  -c, --clippy-only      Run only clippy checks
  -d, --doc-only         Run only documentation build
  -t, --test-only        Run only tests
  -i, --include-ignored  Include ignored tests
  -s, --security         Run security audit (requires cargo-audit)
  --no-features          Don't use the --all-features flag
```

For example, to run only the formatting check:

```bash
./run-ci.sh --format-only
```

Or to include security audits with your CI checks:

```bash
./run-ci.sh --security
```

## Features

- **API Forwarding:** Forwards requests to an Ollama API server
- **Authentication:** Optional API key authentication for model management endpoints
- **IP Allowlisting:** Restrict access to specific IP addresses
- **HTTPS Support:** Optional TLS/SSL encryption for secure connections
- **Logging:** Console and file logging options
- **Database Logging:** Optional request and response logging to SQLite database

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

### With Database Logging

```bash
cargo run -- --port 3001 --ollama-url http://localhost:11434 --db-url "sqlite:logs.db"
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
export PROXY_OLLAMA_DB_URL="sqlite:logs.db"

cargo run
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--port` | Port to listen on (default: 3001) |
| `--ollama-url` | Ollama server URL (default: <http://localhost:11434>) |
| `--log-file` | Output log file (if not specified, logs go to stdout only) |
| `--api-key` | API key required for model management endpoints |
| `--allowed-ips` | List of allowed IP addresses (comma-separated) |
| `--https` | Enable HTTPS mode |
| `--cert-file` | TLS certificate file path (required when HTTPS is enabled) |
| `--key-file` | TLS private key file path (required when HTTPS is enabled) |
| `--host` | Host address to listen on (default: 127.0.0.1, use 0.0.0.0 to listen on all interfaces) |
| `--log-rotate-size` | Maximum log file size before rotation (default: 10MB) |
| `--max-log-files` | Maximum number of rotated log files to keep (default: 0, unlimited) |
| `--db-url` | Database URL for request/response logging in SQLite format (e.g., "sqlite:logs.db") |

## API Endpoints

Documentation for all API endpoints is available at the root URL (e.g., `http://localhost:3001/` or `https://localhost:3001/`).

## Database Logging

The server can log all API requests and responses to a SQLite database for auditing and debugging purposes. This feature is enabled by default but requires a database URL to be specified using the `--db-url` option.

### Database Schema

When enabled, the following information is logged:

- Timestamp of the request
- Client IP address
- HTTP method
- Request path
- Request headers (as JSON)
- Request body (as JSON when possible)
- Response status code
- Response headers (as JSON)
- Response body (as JSON when possible)

### Disabling Database Logging

Database logging is a compiled feature that can be disabled at build time by excluding the "database-logging" feature:

```bash
cargo build --no-default-features
```

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
