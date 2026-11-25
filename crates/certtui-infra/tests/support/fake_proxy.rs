//! In-process HTTP CONNECT proxy for tests (dev/test only).
//!
//! [`FakeProxy::start`] binds `127.0.0.1:0` and serves one [`ProxyBehavior`]
//! until dropped. It records how many connections it accepted and the
//! request line of each CONNECT, and (for the floods) how many bytes it
//! managed to send before the client went away, so tests can prove that the
//! client stops reading.

// Justificativa: this file is compiled by several test crates, each using a
// different subset of the harness API.
#![allow(dead_code)]
// Justificativa: test-only helpers; a panic is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What the proxy does with a CONNECT request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyBehavior {
    /// `200`, then relays to the upstream server.
    Ok,
    /// `407 Proxy Authentication Required`.
    Status407,
    /// `502 Bad Gateway`.
    Status502,
    /// Reads the request and closes without answering.
    CloseImmediately,
    /// A status line followed by one header line of 20 000 bytes.
    HugeHeader,
    /// A status line followed by header lines forever.
    NeverEndingResponse,
    /// Reads the request and never answers.
    Slow,
}

/// Bytes a flooding behavior may send before it gives up.
const FLOOD_CAP: usize = 64 * 1024 * 1024;

/// A running fake proxy.
pub struct FakeProxy {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    flooded: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeProxy {
    /// Starts a proxy that relays to `upstream` (needed for `Ok`).
    pub async fn start(behavior: ProxyBehavior, upstream: Option<SocketAddr>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let flooded = Arc::new(AtomicUsize::new(0));
        let task = {
            let (connections, requests, flooded) = (
                Arc::clone(&connections),
                Arc::clone(&requests),
                Arc::clone(&flooded),
            );
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (requests, flooded) = (Arc::clone(&requests), Arc::clone(&flooded));
                    tokio::spawn(serve(stream, behavior, upstream, requests, flooded));
                }
            })
        };
        Self {
            addr,
            connections,
            requests,
            flooded,
            task,
        }
    }

    /// Where the proxy listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// The request line of every CONNECT received (`CONNECT host:port HTTP/1.1`).
    pub fn request_lines(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Bytes the flooding behaviors managed to send.
    pub fn flooded_bytes(&self) -> usize {
        self.flooded.load(Ordering::SeqCst)
    }
}

impl Drop for FakeProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads the request up to the blank line (at most 8 KiB) and returns its
/// first line.
async fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    while buf.len() < 8192 {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&buf).into_owned();
            return text.lines().next().map(ToOwned::to_owned);
        }
    }
    None
}

async fn serve(
    mut stream: TcpStream,
    behavior: ProxyBehavior,
    upstream: Option<SocketAddr>,
    requests: Arc<Mutex<Vec<String>>>,
    flooded: Arc<AtomicUsize>,
) {
    let Some(line) = read_request(&mut stream).await else {
        return;
    };
    requests.lock().unwrap().push(line);
    match behavior {
        ProxyBehavior::Ok => {
            let Some(upstream) = upstream else { return };
            let Ok(mut server) = TcpStream::connect(upstream).await else {
                return;
            };
            if stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let _ = copy_bidirectional(&mut stream, &mut server).await;
        }
        ProxyBehavior::Status407 => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"test\"\r\n\r\n",
                )
                .await;
        }
        ProxyBehavior::Status502 => {
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        }
        ProxyBehavior::CloseImmediately => {}
        ProxyBehavior::HugeHeader => {
            let mut response = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
            response.extend(std::iter::repeat_n(b'a', 20_000));
            let _ = stream.write_all(&response).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        ProxyBehavior::NeverEndingResponse => {
            if stream.write_all(b"HTTP/1.1 200 OK\r\n").await.is_err() {
                return;
            }
            let chunk =
                b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                    .repeat(64);
            while flooded.load(Ordering::SeqCst) < FLOOD_CAP {
                if stream.write_all(&chunk).await.is_err() {
                    return;
                }
                flooded.fetch_add(chunk.len(), Ordering::SeqCst);
            }
        }
        ProxyBehavior::Slow => {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }
}
