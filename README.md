# Ollama API Proxy Server

[![Rust CI](https://github.com/hehaoqian/ollama-proxy/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/hehaoqian/ollama-proxy/actions/workflows/rust-ci.yml)
[![Security Audit](https://github.com/hehaoqian/ollama-proxy/actions/workflows/security-audit.yml/badge.svg)](https://github.com/hehaoqian/ollama-proxy/actions/workflows/security-audit.yml)

## Disclaimer

1. This project depends on the [ollama](https://github.com/ollama/ollama) project,
but the author of this project is **NOT** affiliated with the [ollama](https://github.com/ollama/ollama) project.

2. WARNING: This project is in early development. Use at your own risk. Use in production is not recommended.

## Introduction

This is a lightweight HTTP server that acts as a proxy for the Ollama API. It forwards requests to an Ollama server and provides additional features like API authentication, IP allowlisting, and HTTPS support.

## Features

- **API Forwarding:** Forwards requests to an Ollama API server
- **Authentication:** Optional API key authentication for model management endpoints
- **IP Allowlisting:** Restrict access to specific IP addresses
- **HTTPS Support:** Optional TLS/SSL encryption for secure connections
- **Logging:** Console and file logging options
- **Database Logging:** Optional request and response logging to SQLite database

## Installation

### System dependency

This project depends on the SQLite C library and development headers (the package that provides `sqlite3.h` and the SQLite library). Install the appropriate system package for your platform before building.

Common packages:

- **Debian / Ubuntu:** `libsqlite3-dev`
	```bash
	sudo apt-get update
	sudo apt-get install -y libsqlite3-dev build-essential pkg-config
	```

- **Fedora / RHEL / CentOS:** `sqlite-devel`
	```bash
	sudo dnf install -y sqlite-devel pkgconfig gcc make
	```

- **Alpine Linux:** `sqlite-dev`
	```bash
	sudo apk add --no-cache sqlite-dev build-base pkgconfig
	```

- **Arch Linux:** `sqlite` (includes headers)
	```bash
	sudo pacman -Syu sqlite base-devel pkgconf
	```

- **macOS (Homebrew):** `sqlite`
	```bash
	brew install sqlite pkg-config
	```

- **Windows:**
	- Option A (MSYS2):
		```powershell
		pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-sqlite3 pkg-config
		```
		Then build using the *MINGW64* shell so the toolchain and headers are discoverable.
	- Option B (vcpkg):
		```powershell
		vcpkg install sqlite3
		# ensure VCPKG_ROOT is set and integrate with your build environment
		```

If you prefer not to install system packages, `libsqlite3-sys` can be built with a bundled SQLite by enabling its `bundled` feature in `Cargo.toml` (see below).

### Vendored / Bundled SQLite (optional)

If installing native packages is inconvenient (CI, containers, or Windows without MSYS2), enable the bundled SQLite feature for the crate that pulls in `libsqlite3-sys`. Example (add or override the dependency in your `Cargo.toml`):

```toml
[dependencies]
# If you directly depend on libsqlite3-sys (or override the transitive dep), enable bundled:
libsqlite3-sys = { version = "*", features = ["bundled"] }
```

Note: using a wildcard version (`"*"`) above is only an example — prefer the specific version used by your project dependency tree or add a `[patch.crates-io]` override if necessary.

### Build & Run

After installing system dependencies (or enabling `bundled`), build and run the server:

```bash
# build (use --release for optimized binary)
cargo build --all-features

# run with example args
cargo run -- --port 3001 --ollama-url http://localhost:11434
```

If you want to disable database logging at build time (it is a compile-time feature), build without default features:

```bash
cargo build --no-default-features
```

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
