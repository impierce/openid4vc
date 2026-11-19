//! HTTP for the crates: the hardened default client, and reading response bodies with a size limit.
//!
//! The `Wallet` and the SIOPv2 `Provider` fetch URLs the other party chooses (`credential_offer_uri`, issuer
//! metadata and the endpoints it names, `request_uri`, `client_metadata_uri`). By default they send these requests
//! with [`http_client`] behind [`PublicHosts`], so a credential offer or an authorization request cannot point them
//! at loopback, private or link-local addresses, and read every body with [`read_body`]. An application that needs
//! another policy (pinned roots, a test CA or local endpoints in development, a proxy) gives its own client to
//! `with_http_client`; [`PublicHosts`] is then not added, and the protections of [`http_client`] are its own.

use std::net::IpAddr;

use anyhow::anyhow;
use reqwest_middleware::{Middleware, Next};

/// The default client of the `Wallet` and the SIOPv2 `Provider`: identity-kit's
/// [`ReqwestClient`](identity_kit::methods::web::ReqwestClient), which
///
/// - speaks HTTPS only, trusting the platform's certificate verifier, over `rustls` with the `ring` provider (made
///   the process default when nothing chose a provider yet; a provider the application installed is kept);
/// - follows no redirect;
/// - refuses a host name that resolves to no public address, and uses no proxy;
/// - times out after ten seconds.
///
/// A URL whose host is an IP address never reaches the resolver; [`PublicHosts`] refuses the non-public ones.
pub fn http_client() -> reqwest::Client {
    identity_kit::methods::web::ReqwestClient::new()
        .expect("the TLS backend initializes, as for `reqwest::Client::new`")
        .client()
        .clone()
}

/// Middleware that refuses a request whose host is an IP address that is not public (see [`http_client`]), before
/// anything is sent. Host names are left to the client's resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicHosts;

#[async_trait::async_trait]
impl Middleware for PublicHosts {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let ip = match request.url().host() {
            Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        if let Some(ip) = ip.filter(|ip| !is_public(*ip)) {
            return Err(reqwest_middleware::Error::Middleware(anyhow!(
                "`{ip}` is not a public address"
            )));
        }
        next.run(request, extensions).await
    }
}

/// Whether `ip` is a public unicast address: not unspecified, loopback, private, link-local, shared (RFC 6598),
/// documentation, benchmarking, multicast, reserved, unique local or in the NAT64 well-known prefix. An IPv4-mapped IPv6 address is judged as its IPv4 address.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b)) // shared address space, RFC 6598
                || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
                || (a == 198 && (18..=19).contains(&b)) // benchmarking, RFC 2544
                || a >= 240) // reserved and broadcast
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || segments[0] == 0x2001 && segments[1] == 0x0db8 // documentation, RFC 3849
                || segments[0] == 0x3fff && segments[1] < 0x1000 // documentation, RFC 9637
                || segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 // benchmarking, RFC 5180
                || segments[0] == 0x0064 && segments[1] == 0xff9b) // NAT64 well-known prefix
        }
    }
}

/// The largest response body the crates read: 1 MiB, far above any metadata document, request object or credential
/// response.
pub const MAX_RESPONSE_BODY: usize = 1 << 20;

/// Reads the body of `response`, failing once it exceeds [`MAX_RESPONSE_BODY`] bytes (after any decoding), so a
/// server cannot make the reader buffer an unbounded body.
pub async fn read_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let too_large = || anyhow!("response body exceeds {MAX_RESPONSE_BODY} bytes");
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BODY as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BODY {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// [`read_body`] as UTF-8 text.
pub async fn read_text(response: reqwest::Response) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_body(response).await?)?)
}

/// [`read_body`] parsed as JSON.
pub async fn read_json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&read_body(response).await?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    /// The error of `result` with its causes, for matching on a message that a cause carries.
    fn error_chain<T>(result: Result<T, impl Into<anyhow::Error>>) -> String {
        format!("{:#}", result.err().map(Into::into).expect("an error"))
    }

    #[test]
    fn public_addresses() {
        for ip in [
            "93.184.215.14",
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
            "2001:4860:4860::8888",
            "::ffff:93.184.215.14",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff:ffff::1",
            "2001:2::1",
            "2001:2:0:ffff::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn public_hosts_refuses_non_public_ip_literals_before_sending() {
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(PublicHosts)
            .build();
        for url in [
            "https://127.0.0.1/",
            "https://10.0.0.1:8443/metadata",
            "https://[::1]/",
            "https://169.254.169.254/latest/meta-data",
        ] {
            let error = error_chain(client.get(url).send().await);
            assert!(error.contains("is not a public address"), "{url}: {error}");
        }
    }

    #[tokio::test]
    async fn default_client_refuses_plain_http_and_hosts_without_a_public_address() {
        let error = error_chain(http_client().get("http://example.com/").send().await);
        assert!(error.contains("URL scheme is not allowed"), "{error}");

        let error = error_chain(http_client().get("https://localhost:9/").send().await);
        assert!(error.contains("resolves to no public address"), "{error}");
    }

    async fn body_of(len: usize) -> anyhow::Result<Vec<u8>> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; len]))
            .mount(&server)
            .await;
        let _ = http_client();
        read_body(reqwest::get(server.uri()).await?).await
    }

    #[tokio::test]
    async fn read_body_stops_at_the_limit() {
        assert_eq!(body_of(MAX_RESPONSE_BODY).await.unwrap().len(), MAX_RESPONSE_BODY);
        assert!(error_chain(body_of(MAX_RESPONSE_BODY + 1).await).contains("exceeds"));
    }

    #[tokio::test]
    async fn read_body_stops_at_the_limit_without_a_content_length() {
        // A chunked body announces no length, so only counting the bytes read catches it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                line.clear();
            }
            let chunk = vec![b'a'; 64 * 1024];
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
            for _ in 0..(MAX_RESPONSE_BODY / chunk.len() + 1) {
                let _ = write!(stream, "{:x}\r\n", chunk.len());
                let _ = stream.write_all(&chunk);
                let _ = stream.write_all(b"\r\n");
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });

        let _ = http_client();
        let response = reqwest::get(url).await.unwrap();
        assert!(response.content_length().is_none());
        assert!(error_chain(read_body(response).await).contains("exceeds"));
    }
}
