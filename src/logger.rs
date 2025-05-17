use chrono::Local;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, Sender};

use crate::size_parser::parse_size;

/// Logger that can write to both console and file with built-in log rotation
pub struct Logger {
    log_sender: Sender<String>,
}

impl Logger {
    /// Creates a new logger with optional log file path, rotation size, and maximum number of rotated files
    pub async fn new(log_path: Option<PathBuf>, log_size_str: String, max_log_files: u32) -> Self {
        // Parse the human-readable size format
        let max_size_bytes = match parse_size(&log_size_str) {
            Ok(size) => size,
            Err(e) => {
                eprintln!(
                    "Error parsing log rotation size '{}': {:?}",
                    log_size_str, e
                );
                eprintln!("Using default size of 10MB");
                10 * 1024 * 1024 // Default to 10MB if parsing fails
            }
        };

        // Create a channel for logging messages
        let (log_sender, mut log_receiver) = mpsc::channel::<String>(100);

        // Clone log_path for use in the spawned task
        let task_log_path = log_path.clone();
        let max_files = max_log_files; // Clone the max_log_files for the task

        // Open log file if path provided
        let log_file = if let Some(path) = log_path.clone() {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
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
            let mut current_size: u64 = if let Some(ref f) = file {
                match f.metadata().await {
                    Ok(metadata) => metadata.len(),
                    Err(_) => 0,
                }
            } else {
                0
            };

            while let Some(message) = log_receiver.recv().await {
                // Always print to console
                println!("{message}");

                // Also log to file if configured
                if file.is_some() {
                    let message_with_newline = format!("{message}\n");
                    let message_bytes = message_with_newline.as_bytes();

                    // Check if we need to rotate the log file
                    if max_size_bytes > 0
                        && current_size + message_bytes.len() as u64 > max_size_bytes
                    {
                        if let Some(ref path) = task_log_path.clone() {
                            drop(file);

                            // Generate timestamp for the rotated log filename
                            let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
                            let rotated_path = path.with_file_name(format!(
                                "{}.{}",
                                path.file_name().unwrap().to_string_lossy(),
                                timestamp
                            ));

                            // Rename the current log file to the rotated filename
                            if let Err(e) = tokio::fs::rename(path, &rotated_path).await {
                                eprintln!("Error rotating log file: {e}");
                            } else {
                                println!("Rotated log file to: {}", rotated_path.display());

                                // Clean up old log files if max_files is set
                                if max_files > 0 {
                                    // Try to clean up old log files
                                    if let Err(e) = cleanup_old_log_files(path, max_files).await {
                                        eprintln!("Error cleaning up old log files: {e}");
                                    }
                                }
                            }

                            // Create a new log file
                            match tokio::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(path)
                                .await
                            {
                                Ok(new_file) => {
                                    file = Some(new_file);
                                    current_size = 0;
                                }
                                Err(e) => {
                                    eprintln!("Error creating new log file after rotation: {e}");
                                    file = None;
                                }
                            }
                        }
                    }

                    // Write to the log file (either existing or newly rotated)
                    if let Some(ref mut f) = file {
                        // Ignore error if we can't write to the file
                        if let Err(e) = f.write_all(message_bytes).await {
                            eprintln!("Error writing to log file: {e}");
                        } else {
                            current_size += message_bytes.len() as u64;
                        }
                        // Try to flush, but ignore errors
                        let _ = f.flush().await;
                    }
                }
            }
        });

        Self { log_sender }
    }

    /// Logs a message to both console and file (if configured)
    pub async fn log(&self, message: &str) {
        // Send message to the logger task
        // If send fails, just print to stderr and continue
        if let Err(e) = self.log_sender.send(message.to_string()).await {
            eprintln!("Failed to send log message: {e}");
            // Fallback to direct console output
            println!("{message}");
        }
    }
}

/// Function to clean up old log files when max limit is reached
pub async fn cleanup_old_log_files(
    log_path: &std::path::Path,
    max_files: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // First, get the base filename to match rotated files
    let base_name = log_path
        .file_name()
        .ok_or("Invalid log path")?
        .to_string_lossy()
        .to_string();

    // Get the directory of the log file
    let dir_path = log_path.parent().unwrap_or(std::path::Path::new("."));

    // Read the directory entries
    let mut entries = Vec::new();
    let mut dir = tokio::fs::read_dir(dir_path).await?;

    // Collect all rotated log files
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if let Some(filename) = path.file_name() {
            let filename_str = filename.to_string_lossy();
            // Check if this is a rotated log file for our base log file
            if filename_str.starts_with(&base_name) && filename_str != base_name {
                entries.push(path);
            }
        }
    }

    // If we have more files than the max allowed, delete the oldest ones
    if entries.len() > max_files as usize {
        // Sort files by modification time (oldest first)
        entries.sort_by(|a, b| {
            let a_meta = std::fs::metadata(a).ok();
            let b_meta = std::fs::metadata(b).ok();

            match (a_meta, b_meta) {
                (Some(a_meta), Some(b_meta)) => a_meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    .cmp(
                        &b_meta
                            .modified()
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                    ),
                _ => std::cmp::Ordering::Equal,
            }
        });

        // Calculate how many files to delete
        let files_to_delete = entries.len() - max_files as usize;

        // Delete the oldest files
        for path in entries.iter().take(files_to_delete) {
            println!("Deleting old log file: {}", path.display());
            tokio::fs::remove_file(path).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_logger_creation() {
        let logger = Logger::new(None, "10MB".to_string(), 0).await;
        assert!(logger.log_sender.capacity() >= 100);
    }

    #[tokio::test]
    async fn test_log_to_console_only() {
        let logger = Logger::new(None, "10MB".to_string(), 0).await;
        // This only tests that the operation doesn't panic
        logger.log("Test log message").await;
        // We can't easily verify console output in a test
    }

    #[tokio::test]
    async fn test_log_to_file() {
        // Create a temporary directory that will be deleted at the end of the test
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let log_path = temp_dir.path().join("test.log");

        // Create a logger with a small max size to trigger rotation quickly
        let logger = Logger::new(Some(log_path.clone()), "100B".to_string(), 3).await;

        // Allow some time for the log file to be created
        sleep(Duration::from_millis(100)).await;

        // Log a message that should go to the file
        logger.log("Test message to file").await;

        // Allow some time for the write to complete
        sleep(Duration::from_millis(100)).await;

        // Verify the message was written to the file
        let content = fs::read_to_string(&log_path).expect("Failed to read log file");
        assert!(content.contains("Test message to file"));
    }

    #[tokio::test]
    async fn test_log_rotation() {
        // Create a temporary directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let log_path = temp_dir.path().join("rotation_test.log");

        // Create file with initial content to have a specific size
        {
            let mut file = fs::File::create(&log_path).expect("Failed to create log file");
            // Write 90 bytes to the file
            file.write_all(&[b'x'; 90])
                .expect("Failed to write to log file");
        }

        // Create a logger with a 100 byte rotation threshold
        let logger = Logger::new(Some(log_path.clone()), "100B".to_string(), 3).await;

        // Allow some time for the logger to initialize
        sleep(Duration::from_millis(100)).await;

        // Log a message that should trigger rotation (> 10 bytes)
        logger.log("This should trigger rotation").await;

        // Allow some time for rotation to occur
        sleep(Duration::from_millis(500)).await;

        // Check if rotation created a new file
        let mut rotated_found = false;
        for entry in fs::read_dir(temp_dir.path()).expect("Failed to read directory") {
            let entry = entry.expect("Failed to read directory entry");
            let filename = entry.file_name().to_string_lossy().to_string();
            if filename.starts_with("rotation_test.log.") {
                rotated_found = true;
                break;
            }
        }

        assert!(rotated_found, "Log rotation did not create a rotated file");
    }
    #[tokio::test]
    async fn test_max_log_files() {
        // Create a temporary directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let log_path = temp_dir.path().join("max_test.log");

        // Create initial log file
        {
            let mut file = fs::File::create(&log_path).expect("Failed to create log file");
            file.write_all(b"initial content")
                .expect("Failed to write to log file");
        }

        // Create 5 rotated log files
        for i in 1..=5 {
            let rotated_path = temp_dir
                .path()
                .join(format!("max_test.log.2025051{}_120000", i));
            fs::write(&rotated_path, format!("rotated content {}", i))
                .expect("Failed to create rotated file");
            // Set modification time to ensure proper ordering
            // Note: This is OS-specific and might not work in all environments
            #[cfg(unix)]
            {
                let now = std::time::SystemTime::now();
                let seconds =
                    now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - (5 - i) * 3600;
                let times = filetime::FileTime::from_unix_time(seconds as i64, 0);
                filetime::set_file_mtime(&rotated_path, times).expect("Failed to set file time");
            }
        }

        // Manually run cleanup with max 3 rotated files
        cleanup_old_log_files(&log_path, 3)
            .await
            .expect("Failed to clean up log files");

        // Count rotated files after manual cleanup
        let rotated_count = count_rotated_files(temp_dir.path(), "max_test.log").await;
        assert_eq!(
            rotated_count, 3,
            "Incorrect number of files after manual cleanup"
        );

        // Create a new logger with max 3 rotated files
        let logger = Logger::new(Some(log_path.clone()), "100B".to_string(), 3).await;

        // Log enough data to trigger a rotation
        for i in 0..30 {
            logger
                .log(&format!("Log message {} to trigger rotation", i))
                .await;
            // Small delay to ensure logs are processed
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Allow time for cleanup to finish
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Count rotated files again after rotation
        let final_count = count_rotated_files(temp_dir.path(), "max_test.log").await;

        // Should still be 3 rotated files (max_files setting)
        assert_eq!(
            final_count, 3,
            "Incorrect number of rotated files after logger rotation"
        );
    }

    // Helper function to count rotated log files
    async fn count_rotated_files(dir_path: &std::path::Path, base_name: &str) -> usize {
        let mut count = 0;
        let mut dir = tokio::fs::read_dir(dir_path)
            .await
            .expect("Failed to read directory");

        while let Some(entry) = dir
            .next_entry()
            .await
            .expect("Failed to get directory entry")
        {
            let path = entry.path();
            if let Some(file_name) = path.file_name() {
                let name = file_name.to_string_lossy();
                // Count only rotated log files (with a timestamp), not the base log file
                if name.starts_with(base_name) && name != base_name {
                    count += 1;
                }
            }
        }

        count
    }
}
