//! The OSC 52 escape sequence: ask the terminal to set its clipboard.

use std::io::Write;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{ClipboardError, ClipboardSink, CopyMethod};

/// `ESC ] 52 ; c ; <base64 of text> BEL`.
#[must_use]
pub fn encode_osc52(text: &str) -> Vec<u8> {
    let mut out = b"\x1b]52;c;".to_vec();
    out.extend_from_slice(STANDARD.encode(text).as_bytes());
    out.push(0x07);
    out
}

/// Sends text to the terminal as OSC 52.
///
/// The terminal never confirms, so a successful copy only means the bytes
/// were written. `W` should be a channel to the event loop, which writes the
/// bytes between two frames: writing straight into the terminal could land in
/// the middle of a frame.
#[derive(Debug)]
pub struct Osc52Sink<W: Write + Send> {
    out: Mutex<W>,
}

impl<W: Write + Send> Osc52Sink<W> {
    /// A sink writing to `out`.
    #[must_use]
    pub fn new(out: W) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }
}

impl<W: Write + Send> ClipboardSink for Osc52Sink<W> {
    fn copy(&self, text: &str) -> Result<CopyMethod, ClipboardError> {
        let bytes = encode_osc52(text);
        let mut out = self
            .out
            .lock()
            .map_err(|_| ClipboardError::Io("terminal writer poisoned".to_owned()))?;
        out.write_all(&bytes)
            .and_then(|()| out.flush())
            .map_err(|error| ClipboardError::Io(error.to_string()))?;
        Ok(CopyMethod::Osc52)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn quando_encode_osc52_deve_gerar_bytes_exatos() {
        assert_eq!(encode_osc52("hello"), b"\x1b]52;c;aGVsbG8=\x07");
    }

    #[test]
    fn quando_texto_vazio_deve_gerar_osc52_com_payload_vazio() {
        assert_eq!(encode_osc52(""), b"\x1b]52;c;\x07");
    }

    #[test]
    fn quando_texto_multibyte_deve_codificar_os_bytes_utf8() {
        assert_eq!(encode_osc52("\u{e9}"), b"\x1b]52;c;w6k=\x07");
    }

    /// A writer whose bytes the test can read back.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn quando_copia_deve_escrever_a_sequencia_inteira_de_uma_vez_e_dizer_osc52() {
        let out = Shared::default();
        let sink = Osc52Sink::new(out.clone());
        assert_eq!(sink.copy("hello"), Ok(CopyMethod::Osc52));
        assert_eq!(*out.0.lock().unwrap(), b"\x1b]52;c;aGVsbG8=\x07");
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn quando_escrita_falha_deve_dar_erro_io() {
        let sink = Osc52Sink::new(Broken);
        assert_eq!(sink.copy("x"), Err(ClipboardError::Io("closed".to_owned())));
    }
}
