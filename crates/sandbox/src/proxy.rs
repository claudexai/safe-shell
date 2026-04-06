use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Check if a hostname matches an allowlist pattern.
/// Supports exact match and wildcard (`*.example.com` also matches `example.com`).
pub fn domain_matches(host: &str, pattern: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host);
    let host = host.to_lowercase();
    let pattern = pattern.to_lowercase();

    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

/// A local HTTP proxy that filters requests by domain allowlist.
/// Runs its own tokio runtime in a background thread.
pub struct DomainFilterProxy {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    _thread: Option<std::thread::JoinHandle<()>>,
    blocked_count: Arc<AtomicUsize>,
}

impl DomainFilterProxy {
    /// Start the proxy on a random port. Returns immediately with the bound port.
    pub fn start(
        allowed_domains: Vec<String>,
        quiet: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let blocked_count = Arc::new(AtomicUsize::new(0));
        let blocked_count_clone = blocked_count.clone();

        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let _ = port_tx.send(port);

                let domains = Arc::new(allowed_domains);

                tokio::select! {
                    _ = accept_loop(listener, domains, blocked_count_clone, quiet) => {}
                    _ = shutdown_rx => {}
                }
            });
        });

        let port = port_rx
            .recv()
            .map_err(|e| format!("Proxy failed to start: {e}"))?;

        Ok(Self {
            port,
            shutdown_tx: Some(shutdown_tx),
            _thread: Some(thread),
            blocked_count,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked_count.load(Ordering::Relaxed)
    }
}

impl Drop for DomainFilterProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    domains: Arc<Vec<String>>,
    blocked_count: Arc<AtomicUsize>,
    quiet: bool,
) {
    while let Ok((stream, _)) = listener.accept().await {
        let domains = domains.clone();
        let blocked = blocked_count.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &domains, &blocked, quiet).await {
                let msg = e.to_string();
                if !msg.contains("Broken pipe") && !msg.contains("Connection reset") {
                    eprintln!("[safe-shell proxy] {msg}");
                }
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    allowed: &[String],
    blocked_count: &AtomicUsize,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let writer = writer;

    // Read the request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0].to_uppercase();
    let target = parts[1].to_string();

    // Read remaining headers
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }

    if method == "CONNECT" {
        handle_connect(reader, writer, &target, allowed, blocked_count, quiet).await
    } else {
        handle_http(
            reader,
            writer,
            &request_line,
            &target,
            &headers,
            allowed,
            blocked_count,
            quiet,
        )
        .await
    }
}

async fn handle_connect(
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    target: &str,
    allowed: &[String],
    blocked_count: &AtomicUsize,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = target.split(':').next().unwrap_or(target);

    if !allowed.iter().any(|p| domain_matches(host, p)) {
        blocked_count.fetch_add(1, Ordering::Relaxed);
        if !quiet {
            eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: blocked network: {host}");
        }
        let msg = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
             [safe-shell] Network blocked: {host} is not in the allowlist\n"
        );
        writer.write_all(msg.as_bytes()).await?;
        return Ok(());
    }

    // Connect to upstream
    match TcpStream::connect(target).await {
        Ok(upstream) => {
            writer
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            let mut client_reader = reader.into_inner();
            let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

            // Bidirectional tunnel
            let c2u = tokio::io::copy(&mut client_reader, &mut upstream_writer);
            let u2c = tokio::io::copy(&mut upstream_reader, &mut writer);

            tokio::select! {
                _ = c2u => {}
                _ = u2c => {}
            }
        }
        Err(e) => {
            let msg = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
                 [safe-shell] Cannot connect to {target}: {e}\n"
            );
            writer.write_all(msg.as_bytes()).await?;
        }
    }

    Ok(())
}

async fn handle_http(
    mut reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    request_line: &str,
    target: &str,
    headers: &[String],
    allowed: &[String],
    blocked_count: &AtomicUsize,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract host from URL: "http://host:port/path"
    let (hostname, port, path) = parse_http_url(target);

    if !allowed.iter().any(|p| domain_matches(&hostname, p)) {
        blocked_count.fetch_add(1, Ordering::Relaxed);
        if !quiet {
            eprintln!("\x1b[33m\u{26a0}\x1b[0m safe-shell: blocked network: {hostname}");
        }
        let msg = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
             [safe-shell] Network blocked: {hostname} is not in the allowlist\n"
        );
        writer.write_all(msg.as_bytes()).await?;
        return Ok(());
    }

    let upstream_addr = format!("{hostname}:{port}");

    match TcpStream::connect(&upstream_addr).await {
        Ok(upstream) => {
            let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

            // Rewrite request line: "GET http://host/path HTTP/1.1" → "GET /path HTTP/1.1"
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            let rewritten = format!("{} {} {}\r\n", parts[0], path, parts[2]);
            upstream_writer.write_all(rewritten.as_bytes()).await?;

            // Forward headers
            for h in headers {
                upstream_writer.write_all(h.as_bytes()).await?;
            }
            upstream_writer.write_all(b"\r\n").await?;

            // Bidirectional copy
            let c2u = tokio::io::copy(&mut reader, &mut upstream_writer);
            let u2c = tokio::io::copy(&mut upstream_reader, &mut writer);

            tokio::select! {
                _ = c2u => {}
                _ = u2c => {}
            }
        }
        Err(e) => {
            let msg = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
                 [safe-shell] Cannot connect to {upstream_addr}: {e}\n"
            );
            writer.write_all(msg.as_bytes()).await?;
        }
    }

    Ok(())
}

fn parse_http_url(url: &str) -> (String, String, String) {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(i) => (&host_port[..i], &host_port[i + 1..]),
        None => (host_port, "80"),
    };

    (host.to_string(), port.to_string(), path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(domain_matches("registry.npmjs.org", "registry.npmjs.org"));
        assert!(domain_matches("Registry.Npmjs.Org", "registry.npmjs.org"));
    }

    #[test]
    fn exact_no_match() {
        assert!(!domain_matches("untrusted.test", "npmjs.org"));
        assert!(!domain_matches("registry.npmjs.org", "npmjs.org"));
    }

    #[test]
    fn wildcard_subdomain() {
        assert!(domain_matches("sub.npmjs.org", "*.npmjs.org"));
        assert!(domain_matches("deep.sub.npmjs.org", "*.npmjs.org"));
    }

    #[test]
    fn wildcard_matches_base() {
        assert!(domain_matches("npmjs.org", "*.npmjs.org"));
    }

    #[test]
    fn wildcard_no_match() {
        assert!(!domain_matches("untrusted.test", "*.npmjs.org"));
        assert!(!domain_matches("npmjs.org.untrusted.test", "*.npmjs.org"));
    }

    #[test]
    fn strips_port() {
        assert!(domain_matches(
            "registry.npmjs.org:443",
            "registry.npmjs.org"
        ));
        assert!(domain_matches("sub.npmjs.org:8080", "*.npmjs.org"));
    }

    #[test]
    fn star_matches_everything() {
        assert!(domain_matches("anything.com", "*"));
        assert!(domain_matches("untrusted.test:8000", "*"));
    }

    #[test]
    fn case_insensitive() {
        assert!(domain_matches("REGISTRY.NPMJS.ORG", "*.npmjs.org"));
        assert!(domain_matches("GitHub.com", "github.com"));
    }

    #[test]
    fn prevents_suffix_attack() {
        assert!(!domain_matches("bad-npmjs.org", "*.npmjs.org"));
        assert!(!domain_matches("fakenpmjs.org", "*.npmjs.org"));
    }

    #[test]
    fn proxy_starts_and_stops() {
        let proxy = DomainFilterProxy::start(vec!["example.com".to_string()], true).unwrap();
        assert!(proxy.port() > 0);
        drop(proxy);
    }

    #[test]
    fn parse_url_with_path() {
        let (h, p, path) = parse_http_url("http://example.com/foo/bar");
        assert_eq!(h, "example.com");
        assert_eq!(p, "80");
        assert_eq!(path, "/foo/bar");
    }

    #[test]
    fn parse_url_with_port() {
        let (h, p, path) = parse_http_url("http://example.com:8080/api");
        assert_eq!(h, "example.com");
        assert_eq!(p, "8080");
        assert_eq!(path, "/api");
    }

    #[test]
    fn parse_url_no_path() {
        let (h, p, path) = parse_http_url("http://example.com");
        assert_eq!(h, "example.com");
        assert_eq!(p, "80");
        assert_eq!(path, "/");
    }

    // --- Edge cases in domain matching ---

    #[test]
    fn empty_host_no_crash() {
        assert!(!domain_matches("", "example.com"));
        assert!(!domain_matches("", "*.example.com"));
    }

    #[test]
    fn empty_pattern_no_crash() {
        assert!(!domain_matches("example.com", ""));
    }

    #[test]
    fn subdomain_of_tld_not_confused() {
        // *.com should match sub.com
        assert!(domain_matches("untrusted.com", "*.com"));
        assert!(domain_matches("com", "*.com"));
    }

    #[test]
    fn host_with_trailing_dot() {
        // DNS allows trailing dot (FQDN)
        // Our matcher strips port but not trailing dot — this is a known edge case
        // Attackers shouldn't be able to bypass by adding a trailing dot
        let result = domain_matches("untrusted.test.", "untrusted.test");
        // Either match or not — just don't crash
        let _ = result;
    }

    #[test]
    fn wildcard_pattern_with_port() {
        assert!(domain_matches("sub.example.com:8080", "*.example.com"));
    }

    #[test]
    fn multiple_ports_in_host_no_crash() {
        // Malformed host — should not crash, port strip takes first ':'
        let _ = domain_matches("untrusted.test:80:443", "untrusted.test");
    }
}
