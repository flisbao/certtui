//! Byte-budgeted wrapper around an async stream.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Error carried inside the `io::Error` returned when the read budget is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudgetExceeded {
    /// The configured maximum number of bytes that may be read.
    pub limit: usize,
}

impl fmt::Display for ByteBudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "read byte budget of {} bytes exceeded", self.limit)
    }
}

impl std::error::Error for ByteBudgetExceeded {}

/// Stream wrapper that bounds how many bytes may be read from the inner stream.
///
/// Only reads are counted; writes, flushes and shutdowns are delegated untouched.
///
/// Budget rule: with `remaining = max_read_bytes - bytes_read`, every `poll_read`
/// offers the inner stream at most `remaining + 1` bytes of buffer space, so the
/// inner source is never asked for more than `max_read_bytes + 1` bytes in total.
/// If the inner stream produces more than `remaining` bytes in a single read (that
/// is, the `max_read_bytes + 1`-th byte is observed), the whole read is discarded
/// and `poll_read` fails with an `io::Error` of kind `Other` wrapping
/// [`ByteBudgetExceeded`]. The failure is sticky: later reads fail the same way
/// without touching the inner stream. Reading exactly `max_read_bytes` bytes
/// followed by EOF succeeds.
#[derive(Debug)]
pub struct LimitedStream<S> {
    inner: S,
    max_read_bytes: usize,
    bytes_read: usize,
    exceeded: bool,
}

impl<S> LimitedStream<S> {
    /// Wraps `inner`, allowing at most `max_read_bytes` bytes to be read.
    pub fn new(inner: S, max_read_bytes: usize) -> Self {
        Self {
            inner,
            max_read_bytes,
            bytes_read: 0,
            exceeded: false,
        }
    }

    /// Bytes delivered to the caller so far; never more than `max_read_bytes`.
    ///
    /// The over-budget byte (and the rest of the read that contained it) is never
    /// delivered, so it is not counted.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    fn budget_error(&self) -> io::Error {
        io::Error::other(ByteBudgetExceeded {
            limit: self.max_read_bytes,
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LimitedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.exceeded {
            return Poll::Ready(Err(this.budget_error()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining = this.max_read_bytes.saturating_sub(this.bytes_read);
        let cap = remaining.saturating_add(1).min(buf.remaining());
        let read = {
            let window = buf.initialize_unfilled_to(cap);
            let mut limited = ReadBuf::new(window);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => limited.filled().len(),
                other => return other,
            }
        };
        if read > remaining {
            this.exceeded = true;
            return Poll::Ready(Err(this.budget_error()));
        }
        buf.advance(read);
        this.bytes_read = this.bytes_read.saturating_add(read);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// Endless source that records how many bytes were pulled from it.
    struct InfiniteSource {
        pulled: Arc<AtomicUsize>,
    }

    impl AsyncRead for InfiniteSource {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining();
            buf.put_slice(&vec![0xAB; n]);
            self.pulled.fetch_add(n, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    fn budget_error(err: &io::Error) -> Option<ByteBudgetExceeded> {
        err.get_ref()?.downcast_ref::<ByteBudgetExceeded>().copied()
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    #[tokio::test]
    async fn quando_leitura_cabe_no_orcamento_deve_passar_bytes_intactos() {
        let data = payload(100);
        let mut stream = LimitedStream::new(data.as_slice(), 1024);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
        assert_eq!(stream.bytes_read(), 100);
    }

    #[tokio::test]
    async fn quando_leitura_e_exatamente_o_limite_deve_passar() {
        let data = payload(64);
        let mut stream = LimitedStream::new(data.as_slice(), 64);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
        assert_eq!(stream.bytes_read(), 64);
    }

    #[tokio::test]
    async fn quando_eof_antes_do_limite_deve_continuar_dando_eof() {
        let data = payload(3);
        let mut stream = LimitedStream::new(data.as_slice(), 10);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
        let mut extra = [0u8; 4];
        assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
        assert_eq!(stream.bytes_read(), 3);
    }

    #[tokio::test]
    async fn quando_leitura_passa_do_orcamento_deve_dar_byte_budget_exceeded() {
        let data = payload(65);
        let mut stream = LimitedStream::new(data.as_slice(), 64);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(budget_error(&err), Some(ByteBudgetExceeded { limit: 64 }));
        assert!(out.len() <= 64);
        assert!(stream.bytes_read() <= 64);
    }

    #[tokio::test]
    async fn quando_fonte_e_infinita_deve_parar_em_no_maximo_orcamento_mais_um_chunk() {
        let pulled = Arc::new(AtomicUsize::new(0));
        let source = InfiniteSource {
            pulled: Arc::clone(&pulled),
        };
        let mut stream = LimitedStream::new(source, 1000);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(budget_error(&err), Some(ByteBudgetExceeded { limit: 1000 }));
        let pulled = pulled.load(Ordering::SeqCst);
        assert!(pulled > 1000, "pulled {pulled}");
        assert!(pulled <= 1001, "pulled {pulled}");
        assert!(out.len() <= 1000);
    }

    #[tokio::test]
    async fn quando_limite_e_zero_deve_aceitar_fonte_vazia() {
        let mut stream = LimitedStream::new(&b""[..], 0);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), 0);
    }

    #[tokio::test]
    async fn quando_limite_e_zero_deve_rejeitar_um_byte() {
        let mut stream = LimitedStream::new(&b"x"[..], 0);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(budget_error(&err), Some(ByteBudgetExceeded { limit: 0 }));
        assert_eq!(out.len(), 0);
        assert_eq!(stream.bytes_read(), 0);
    }

    #[tokio::test]
    async fn quando_estourou_o_orcamento_deve_manter_o_erro_nas_leituras_seguintes() {
        let data = payload(10);
        let mut stream = LimitedStream::new(data.as_slice(), 4);
        let mut buf = [0u8; 16];
        let first = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(budget_error(&first), Some(ByteBudgetExceeded { limit: 4 }));
        let before = stream.bytes_read();
        for _ in 0..3 {
            let again = stream.read(&mut buf).await.unwrap_err();
            assert_eq!(budget_error(&again), Some(ByteBudgetExceeded { limit: 4 }));
        }
        assert_eq!(stream.bytes_read(), before);
    }

    #[tokio::test]
    async fn quando_buffer_do_chamador_e_vazio_deve_nao_estourar_orcamento() {
        let mut stream = LimitedStream::new(&b"abc"[..], 0);
        let mut empty: [u8; 0] = [];
        assert_eq!(stream.read(&mut empty).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn quando_escrita_deve_nao_contar_no_orcamento() {
        let (near, mut far) = duplex(256);
        let mut stream = LimitedStream::new(near, 10);
        let outgoing = payload(100);
        stream.write_all(&outgoing).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.bytes_read(), 0);

        let mut received = vec![0u8; 100];
        far.read_exact(&mut received).await.unwrap();
        assert_eq!(received, outgoing);

        far.write_all(b"hello").await.unwrap();
        let mut incoming = [0u8; 5];
        stream.read_exact(&mut incoming).await.unwrap();
        assert_eq!(&incoming, b"hello");
        assert_eq!(stream.bytes_read(), 5);

        stream.shutdown().await.unwrap();
    }
}
