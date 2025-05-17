// Parse human-readable size formats like "1KB", "10MB", etc.

#[derive(Debug, PartialEq)]
pub enum SizeParseError {
    Format,
    Unit,
    Number,
}

/// Parse a human-readable size string into bytes
///
/// Supports formats:
/// - Plain number (interpreted as bytes): "1024"
/// - Size with unit: "1KB", "10MB", "1.5GB", etc.
///
/// Supported units (case-insensitive):
/// - B, Byte, Bytes: bytes
/// - K, KB, KiB: kilobytes (1024 bytes)
/// - M, MB, MiB: megabytes (1024^2 bytes)
/// - G, GB, GiB: gigabytes (1024^3 bytes)
/// - T, TB, TiB: terabytes (1024^4 bytes)
pub fn parse_size(size_str: &str) -> Result<u64, SizeParseError> {
    // Strip whitespace
    let size_str = size_str.trim();

    // If it's just a number, interpret as bytes
    if size_str.chars().all(|c| c.is_ascii_digit()) {
        return size_str
            .parse::<u64>()
            .map_err(|_| SizeParseError::Number);
    }

    // Find the split between number and unit
    let mut num_end = 0;
    for (i, c) in size_str.char_indices() {
        if !c.is_ascii_digit() && c != '.' {
            num_end = i;
            break;
        }
    }

    if num_end == 0 {
        return Err(SizeParseError::Format);
    }

    // Parse the number part
    let num_str = &size_str[..num_end];
    let number = num_str
        .parse::<f64>()
        .map_err(|_| SizeParseError::Number)?;

    // Parse the unit part
    let unit = size_str[num_end..].trim().to_lowercase();

    // Convert to bytes based on the unit
    let bytes = match unit.as_str() {
        "b" | "byte" | "bytes" => number,
        "k" | "kb" | "kib" => number * 1024.0,
        "m" | "mb" | "mib" => number * 1024.0 * 1024.0,
        "g" | "gb" | "gib" => number * 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => number * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(SizeParseError::Unit),
    };

    if bytes < 0.0 {
        return Err(SizeParseError::Number);
    }

    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_truncation)]
    let bytes: u64 = bytes as u64;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        // Test bytes
        assert_eq!(parse_size("1024").unwrap(), 1024);

        // Test kilobytes
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1KiB").unwrap(), 1024);

        // Test megabytes
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1MiB").unwrap(), 1024 * 1024);

        // Test gigabytes
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);

        // Test decimal values
        #[allow(clippy::cast_possible_truncation)]
        assert_eq!(parse_size("1.5MB").unwrap(), (1.5 * 1024.0 * 1024.0) as u64);

        // Test whitespace
        assert_eq!(parse_size(" 1MB ").unwrap(), 1024 * 1024);

        // Test case-insensitivity
        assert_eq!(parse_size("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1Mb").unwrap(), 1024 * 1024);

        // Test errors
        assert!(parse_size("").is_err());
        assert!(parse_size("MB").is_err());
        assert!(parse_size("1XB").is_err());
    }
}
