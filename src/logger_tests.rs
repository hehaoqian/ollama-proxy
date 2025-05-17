//! Test suite for the logger module.

use std::time::Duration;
use tempfile::tempdir;
use tokio::fs;
use tokio::test;
use tokio::time::sleep;

use crate::logger::{Logger, cleanup_old_log_files};

#[test]
async fn test_logger_no_file() {
    // Create a logger without a log file
    let logger = Logger::new(None, "10MB".to_string(), 0).await;

    // Log a test message
    logger.log("Test message with no file").await;

    // Since there's no easy way to capture stdout in tests,
    // we just verify that the operation doesn't panic
}

#[test]
async fn test_logger_with_file() {
    // Create a temporary directory
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("test.log");

    // Create a logger with a log file
    let logger = Logger::new(Some(log_path.clone()), "10MB".to_string(), 0).await;

    // Log a test message
    logger.log("Test message with file").await;

    // Allow some time for logging to complete
    sleep(Duration::from_millis(100)).await;

    // Verify the message was written to the file
    let content = fs::read_to_string(&log_path).await.unwrap();
    assert!(content.contains("Test message with file"));
}

#[test]
async fn test_log_rotation() {
    // Create a temporary directory
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("rotation.log");

    // Create a log file with initial content
    fs::write(&log_path, "Initial content that takes up space")
        .await
        .unwrap();

    // Create a logger with a small rotation size
    let logger = Logger::new(Some(log_path.clone()), "50B".to_string(), 3).await;

    // Log messages to trigger rotation
    for i in 1..=10 {
        logger
            .log(&format!("Log message {i} to trigger rotation"))
            .await;
        // Small delay to ensure logs are processed
        sleep(Duration::from_millis(50)).await;
    }

    // Wait for rotation to complete
    sleep(Duration::from_millis(200)).await;

    // Check if rotated files exist
    let mut dir_entries = fs::read_dir(temp_dir.path()).await.unwrap();
    let mut rotated_files = 0;

    while let Some(entry) = dir_entries.next_entry().await.unwrap() {
        let path = entry.path();
        if let Some(file_name) = path.file_name() {
            if file_name.to_string_lossy().starts_with("rotation.log.") {
                rotated_files += 1;
            }
        }
    }

    // Should be at least one rotated file
    assert!(rotated_files > 0, "No rotated log files found");
}

#[test]
async fn test_max_log_files() {
    // Create a temporary directory
    let temp_dir = tempdir().unwrap();
    let base_path = temp_dir.path().join("max_test.log");

    // Create several rotated log files with timestamps
    let timestamps = [
        "20250101_120000",
        "20250101_120100",
        "20250101_120200",
        "20250101_120300",
        "20250101_120400",
    ];

    for ts in timestamps.iter() {
        let rotated_path = temp_dir.path().join(format!("max_test.log.{}", ts));
        fs::write(&rotated_path, format!("Rotated content for {}", ts))
            .await
            .unwrap();
    }

    // Run cleanup with max 2 files
    cleanup_old_log_files(&base_path, 2).await.unwrap();

    // Count remaining files
    let mut dir_entries = fs::read_dir(temp_dir.path()).await.unwrap();
    let mut remaining_files = 0;

    while let Some(entry) = dir_entries.next_entry().await.unwrap() {
        let path = entry.path();
        if let Some(file_name) = path.file_name() {
            if file_name.to_string_lossy().starts_with("max_test.log.") {
                remaining_files += 1;
            }
        }
    }

    // Should be exactly 2 files left (our specified max)
    assert_eq!(
        remaining_files, 2,
        "Incorrect number of files remaining after cleanup"
    );
}
