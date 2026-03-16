//! Input collection from file, comma-separated args, or stdin.

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};

pub(crate) async fn collect_input(list: Option<&str>, silent: bool) -> Result<Vec<String>> {
    let mut hosts: Vec<String> = Vec::new();

    if let Some(arg) = list {
        // Check if it looks like a file path (no commas, and the file exists)
        if !arg.contains(',') {
            // Try to open as file
            match tokio::fs::File::open(arg).await {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let mut lines = reader.lines();
                    while let Some(line) = lines.next_line().await? {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            hosts.push(trimmed);
                        }
                    }
                    return Ok(hosts);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if (arg.ends_with(".txt") || arg.ends_with(".lst")) && !silent {
                        eprintln!("[WARN] File not found: {arg}, treating as hostname");
                    }
                    hosts.push(arg.trim().to_string());
                    return Ok(hosts);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Cannot open input file '{}': {}", arg, e));
                }
            }
        } else {
            // Comma-separated list
            for part in arg.split(',') {
                let trimmed = part.trim().to_string();
                if !trimmed.is_empty() {
                    hosts.push(trimmed);
                }
            }
            return Ok(hosts);
        }
    }

    // Fall back to stdin
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            hosts.push(trimmed);
        }
    }

    Ok(hosts)
}
