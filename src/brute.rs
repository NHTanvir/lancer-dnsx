//! Brute-force input generation: word.domain pairs from a wordlist.
//!
//! Activated when the user passes `-d/--domain`. The wordlist comes from
//! `-w/--wordlist` if provided; otherwise we fall back to an embedded
//! top-100 list. Auto-wildcard detection is always forced on by the
//! caller in this mode to prevent the false-positive flood that wildcard
//! zones produce against a brute-force probe.

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Embedded fallback wordlist (top-100 common subdomain labels).
/// Used when the user passes `-d` without `-w`.
const EMBEDDED_TOP_100_WORDLIST: &str = include_str!("../wordlists/top-100.txt");

/// Parse a comma-separated `--domain` value into individual target domains.
///
/// Returns an error if any non-empty segment doesn't look like a domain
/// (no dot, contains whitespace, etc.). Empty segments are skipped so
/// trailing commas are forgiving.
pub(crate) fn parse_domains(arg: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for part in arg.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.contains('.')
            || trimmed.starts_with('.')
            || trimmed.ends_with('.')
            || trimmed.chars().any(char::is_whitespace)
        {
            anyhow::bail!(
                "--domain must be a valid domain name (e.g., target.com), got: {trimmed}"
            );
        }
        out.push(trimmed.to_string());
    }
    if out.is_empty() {
        anyhow::bail!("--domain was empty after parsing");
    }
    Ok(out)
}

/// Load a wordlist from `path`. Lines are trimmed; blanks and `#` comment
/// lines are skipped.
async fn load_wordlist_file(path: &str) -> Result<Vec<String>> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Cannot open wordlist file '{path}'"))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut out = Vec::new();
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

/// Parse the embedded top-100 wordlist into individual labels.
fn embedded_wordlist() -> Vec<String> {
    EMBEDDED_TOP_100_WORDLIST
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Generate brute-force input hostnames: `word.domain` for every (word,
/// domain) pair.
///
/// * `domain_arg`  -- value of `--domain` (comma-separated)
/// * `wordlist`    -- value of `--wordlist`; `None` means use the embedded list
/// * `silent`      -- suppress informational messages on stderr
pub(crate) async fn generate_brute_input(
    domain_arg: &str,
    wordlist: Option<&str>,
    silent: bool,
) -> Result<Vec<String>> {
    let domains = parse_domains(domain_arg)?;

    let words: Vec<String> = match wordlist {
        Some(path) => {
            let w = load_wordlist_file(path).await?;
            if w.is_empty() {
                anyhow::bail!("Wordlist '{path}' is empty");
            }
            w
        }
        None => {
            if !silent {
                eprintln!(
                    "[INFO] No -w provided; using embedded top-100 wordlist"
                );
            }
            embedded_wordlist()
        }
    };

    if !silent {
        eprintln!(
            "[INFO] Brute mode: {} domain(s) x {} word(s) = {} hostnames",
            domains.len(),
            words.len(),
            domains.len().saturating_mul(words.len())
        );
    }

    let mut out = Vec::with_capacity(domains.len().saturating_mul(words.len()));
    for domain in &domains {
        for word in &words {
            out.push(format!("{word}.{domain}"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domains_basic() {
        let v = parse_domains("foo.com,bar.org").unwrap();
        assert_eq!(v, vec!["foo.com".to_string(), "bar.org".to_string()]);
    }

    #[test]
    fn parse_domains_trims_and_skips_empty() {
        let v = parse_domains("  foo.com , , bar.org ,").unwrap();
        assert_eq!(v, vec!["foo.com".to_string(), "bar.org".to_string()]);
    }

    #[test]
    fn parse_domains_rejects_no_dot() {
        assert!(parse_domains("foo").is_err());
    }

    #[test]
    fn parse_domains_rejects_leading_dot() {
        assert!(parse_domains(".foo.com").is_err());
    }

    #[test]
    fn parse_domains_rejects_whitespace_inside() {
        assert!(parse_domains("foo .com").is_err());
    }

    #[test]
    fn parse_domains_rejects_all_empty() {
        assert!(parse_domains(",,").is_err());
    }

    #[test]
    fn embedded_wordlist_has_entries() {
        let w = embedded_wordlist();
        assert!(!w.is_empty(), "embedded wordlist should not be empty");
        assert!(w.contains(&"www".to_string()));
        assert!(w.contains(&"mail".to_string()));
    }

    #[tokio::test]
    async fn generate_brute_input_uses_embedded_default() {
        let hosts = generate_brute_input("example.com", None, true).await.unwrap();
        assert!(hosts.contains(&"www.example.com".to_string()));
        assert!(hosts.contains(&"mail.example.com".to_string()));
    }

    #[tokio::test]
    async fn generate_brute_input_multi_domain() {
        let hosts = generate_brute_input("a.com,b.com", None, true).await.unwrap();
        assert!(hosts.contains(&"www.a.com".to_string()));
        assert!(hosts.contains(&"www.b.com".to_string()));
    }
}
