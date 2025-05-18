// filepath: /home/main/src/ollama_proxy/src/db_logger.rs
use chrono::{DateTime, Utc};
use hyper::{HeaderMap, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "database-logging")]
use sqlx::{Pool, Sqlite, sqlite::SqlitePool};

/// Database logger implementation for SQLite
#[derive(Clone)]
pub struct DbLogger {
    #[cfg(feature = "database-logging")]
    pool: Option<Arc<Pool<Sqlite>>>,

    #[cfg(not(feature = "database-logging"))]
    _dummy: (), // Empty field for when database-logging is disabled
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestLog {
    timestamp: DateTime<Utc>,
    client_ip: String,
    method: String,
    path: String,
    status_code: Option<u16>,
    direction: String, // "request" or "response"
    headers: Value,    // JSON representation of headers
    body: Value,       // JSON representation of body if it's valid JSON
}

impl DbLogger {
    pub async fn new(db_url: Option<String>) -> Self {
        #[cfg(feature = "database-logging")]
        {
            if let Some(url) = db_url {
                match SqlitePool::connect(&url).await {
                    Ok(pool) => {
                        // Create tables if they don't exist
                        if let Err(e) = Self::initialize_database(&pool).await {
                            eprintln!("Failed to initialize database: {e}");
                            return Self { pool: None };
                        }
                        return Self {
                            pool: Some(Arc::new(pool)),
                        };
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to database: {e}");
                        return Self { pool: None };
                    }
                }
            }
            Self { pool: None }
        }

        #[cfg(not(feature = "database-logging"))]
        {
            Self { _dummy: () }
        }
    }

    #[cfg(feature = "database-logging")]
    async fn initialize_database(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER,
                direction TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn log_request(
        &self,
        client_ip: &SocketAddr,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) {
        #[cfg(feature = "database-logging")]
        if let Some(pool) = &self.pool {
            // Try to parse body as JSON
            let body_json = if body.is_empty() {
                serde_json::json!({ "content": "<empty>" })
            } else if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                value
            } else {
                serde_json::json!({ "content": String::from_utf8_lossy(body) })
            };

            // Convert headers to JSON
            let headers_json = headers
                .iter()
                .map(|(k, v)| {
                    let key = k.as_str().to_string();
                    let value =
                        serde_json::Value::String(v.to_str().unwrap_or("<binary>").to_string());
                    (key, value)
                })
                .collect::<serde_json::Map<String, serde_json::Value>>();

            let log = RequestLog {
                timestamp: Utc::now(),
                client_ip: client_ip.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                status_code: None, // This is a request, so no status code yet
                direction: "request".to_string(),
                headers: serde_json::Value::Object(headers_json),
                body: body_json,
            };

            if let Err(e) = self.save_log(&log, pool).await {
                eprintln!("Failed to log request to database: {e}");
            }
        }
    }

    pub async fn log_response(
        &self,
        client_ip: &SocketAddr,
        method: &Method,
        path: &str,
        status: &StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) {
        #[cfg(feature = "database-logging")]
        if let Some(pool) = &self.pool {
            // Try to parse body as JSON
            let body_json = if body.is_empty() {
                serde_json::json!({ "content": "<empty>" })
            } else if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                value
            } else {
                serde_json::json!({ "content": String::from_utf8_lossy(body) })
            };

            // Convert headers to JSON
            let headers_json = headers
                .iter()
                .map(|(k, v)| {
                    let key = k.as_str().to_string();
                    let value =
                        serde_json::Value::String(v.to_str().unwrap_or("<binary>").to_string());
                    (key, value)
                })
                .collect::<serde_json::Map<String, serde_json::Value>>();

            let log = RequestLog {
                timestamp: Utc::now(),
                client_ip: client_ip.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                status_code: Some(status.as_u16()),
                direction: "response".to_string(),
                headers: serde_json::Value::Object(headers_json),
                body: body_json,
            };

            if let Err(e) = self.save_log(&log, pool).await {
                eprintln!("Failed to log response to database: {e}");
            }
        }
    }

    #[cfg(feature = "database-logging")]
    async fn save_log(&self, log: &RequestLog, pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
        // Convert log to strings for SQLite
        let headers_str = serde_json::to_string(&log.headers).unwrap_or_default();
        let body_str = serde_json::to_string(&log.body).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT INTO request_logs
            (timestamp, client_ip, method, path, status_code, direction, headers, body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(log.timestamp.to_rfc3339())
        .bind(&log.client_ip)
        .bind(&log.method)
        .bind(&log.path)
        .bind(log.status_code)
        .bind(&log.direction)
        .bind(headers_str)
        .bind(body_str)
        .execute(pool)
        .await?;

        Ok(())
    }
}
