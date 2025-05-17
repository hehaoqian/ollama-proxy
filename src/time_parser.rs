//! Utility functions for parsing time strings

/// Parse time string in format like "1s", "1m2s", "3h1m5s", "-1s" (infinite)
/// Returns the time in seconds, negative value means infinite
pub fn parse_time_string(time_str: &str) -> Result<i64, String> {
    if time_str.is_empty() {
        return Err("Empty time string".to_string());
    }

    // Handle negative time (infinite)
    if time_str.starts_with('-') {
        return Ok(-1);
    }

    let mut total_seconds = 0i64;
    let mut current_number = 0i64;
    let chars = time_str.chars();

    for c in chars {
        if c.is_ascii_digit() {
            current_number = current_number * 10 + i64::from(c.to_digit(10).unwrap());
        } else {
            match c {
                'h' => {
                    total_seconds += current_number * 3600; // hours to seconds
                    current_number = 0;
                }
                'm' => {
                    total_seconds += current_number * 60; // minutes to seconds
                    current_number = 0;
                }
                's' => {
                    total_seconds += current_number; // seconds
                    current_number = 0;
                }
                _ => {
                    return Err(format!("Invalid time unit: {c}"));
                }
            }
        }
    }

    // If there's a trailing number without a unit, assume it's seconds
    if current_number > 0 {
        total_seconds += current_number;
    }

    Ok(total_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_time_string() {
        // Test seconds
        assert_eq!(parse_time_string("5s").unwrap(), 5);
        assert_eq!(parse_time_string("30s").unwrap(), 30);

        // Test minutes
        assert_eq!(parse_time_string("2m").unwrap(), 120);

        // Test hours
        assert_eq!(parse_time_string("1h").unwrap(), 3600);

        // Test combinations
        assert_eq!(parse_time_string("1h30m").unwrap(), 5400);
        assert_eq!(parse_time_string("2h15m30s").unwrap(), 8130);

        // Test without units (assume seconds)
        assert_eq!(parse_time_string("42").unwrap(), 42);

        // Test negative (infinite)
        assert_eq!(parse_time_string("-1s").unwrap(), -1);
        assert_eq!(parse_time_string("-1").unwrap(), -1);

        // Test empty string
        assert!(parse_time_string("").is_err());

        // Test invalid unit
        assert!(parse_time_string("5x").is_err());
    }
}
