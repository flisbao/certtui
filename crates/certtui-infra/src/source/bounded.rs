use std::io::Read;

use certtui_app::error::LoadError;

const INITIAL_CAPACITY: usize = 64 * 1024;
const READ_CHUNK: usize = 8 * 1024;

/// Reads at most `limit + 1` bytes and rejects input beyond `limit`.
// Justificativa: o adaptador de fonte será conectado à porta no Task 15.
#[allow(dead_code)]
pub(crate) fn read_limited<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, LoadError> {
    read_limited_inner(reader, limit).0
}

fn read_limited_inner<R: Read>(reader: R, limit: usize) -> (Result<Vec<u8>, LoadError>, usize) {
    let initial_capacity = limit.saturating_add(1).min(INITIAL_CAPACITY);
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut reader = reader.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1));
    let mut chunk = [0; READ_CHUNK];

    loop {
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return (Err(LoadError::Io(error.to_string())), bytes.capacity()),
        };
        if read == 0 {
            let capacity = bytes.capacity();
            return (Ok(bytes), capacity);
        }
        if read > limit.saturating_sub(bytes.len()) {
            return (Err(LoadError::TooLarge { limit }), bytes.capacity());
        }
        if bytes.len().saturating_add(read) > bytes.capacity() {
            let required_capacity = bytes.len().saturating_add(read);
            let growth_ceiling = limit.saturating_add(INITIAL_CAPACITY);
            let doubled_capacity = bytes.capacity().saturating_mul(2);
            let target_capacity = required_capacity.max(doubled_capacity).min(growth_ceiling);
            bytes.reserve_exact(target_capacity.saturating_sub(bytes.len()));
        }
        bytes.extend(chunk.iter().take(read).copied());
    }
}

#[cfg(test)]
fn read_limited_with_capacity_probe<R: Read>(
    reader: R,
    limit: usize,
) -> (Result<Vec<u8>, LoadError>, usize) {
    read_limited_inner(reader, limit)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use certtui_app::error::LoadError;

    use super::{read_limited, read_limited_with_capacity_probe};

    #[test]
    fn quando_entrada_tem_exatamente_o_limite_deve_aceitar() {
        assert_eq!(read_limited(&b"abcd"[..], 4), Ok(b"abcd".to_vec()));
    }

    #[test]
    fn quando_entrada_tem_limite_mais_um_deve_dar_too_large() {
        assert_eq!(
            read_limited(&b"abcde"[..], 4),
            Err(LoadError::TooLarge { limit: 4 })
        );
    }

    struct InfiniteReader {
        reads: usize,
    }

    impl Read for InfiniteReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(b'A');
            self.reads += buf.len();
            Ok(buf.len())
        }
    }

    #[test]
    fn quando_leitor_e_infinito_deve_parar_em_limite_mais_um() {
        let limit = 100;
        let mut reader = InfiniteReader { reads: 0 };
        assert_eq!(
            read_limited(&mut reader, limit),
            Err(LoadError::TooLarge { limit })
        );
        assert_eq!(reader.reads, limit + 1);
    }

    struct InterruptedReader {
        data: &'static [u8],
        bytes_read: usize,
        interrupted_before_data: bool,
        interrupted_during_data: bool,
    }

    impl InterruptedReader {
        fn new(data: &'static [u8]) -> Self {
            Self {
                data,
                bytes_read: 0,
                interrupted_before_data: false,
                interrupted_during_data: false,
            }
        }
    }

    impl Read for InterruptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted_before_data {
                self.interrupted_before_data = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.bytes_read == 2 && !self.interrupted_during_data {
                self.interrupted_during_data = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }

            let mut copied = 0;
            for (target, source) in buf
                .iter_mut()
                .zip(self.data.iter().skip(self.bytes_read))
                .take(2)
            {
                *target = *source;
                copied += 1;
            }
            self.bytes_read += copied;
            Ok(copied)
        }
    }

    #[test]
    fn quando_leitor_e_interrompido_antes_e_durante_deve_retomar_e_aceitar_bytes() {
        let mut reader = InterruptedReader::new(b"abcd");
        assert_eq!(read_limited(&mut reader, 4), Ok(b"abcd".to_vec()));
        assert_eq!(reader.bytes_read, 4);
        assert!(reader.interrupted_before_data);
        assert!(reader.interrupted_during_data);
    }

    #[test]
    fn quando_interrupcoes_antecedem_excesso_deve_parar_em_limite_mais_um() {
        let limit = 4;
        let mut reader = InterruptedReader::new(b"abcdefgh");
        assert_eq!(
            read_limited(&mut reader, limit),
            Err(LoadError::TooLarge { limit })
        );
        assert_eq!(reader.bytes_read, limit + 1);
        assert!(reader.interrupted_before_data);
        assert!(reader.interrupted_during_data);
    }

    #[test]
    fn quando_16mib_mais_1_deve_rejeitar_sem_alocar_mais_que_16mib_mais_64kib() {
        let limit = 16 * 1024 * 1024;
        let reader = InfiniteReader { reads: 0 };
        let (result, capacity) = read_limited_with_capacity_probe(reader, limit);
        assert_eq!(result, Err(LoadError::TooLarge { limit }));
        assert!(capacity <= limit + 64 * 1024);
    }

    #[test]
    fn quando_limite_e_zero_deve_aceitar_entrada_vazia() {
        assert_eq!(read_limited(&b""[..], 0), Ok(Vec::new()));
    }

    #[test]
    fn quando_limite_e_maximo_deve_aceitar_entrada_vazia_sem_overflow() {
        assert_eq!(read_limited(&b""[..], usize::MAX), Ok(Vec::new()));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("falha de leitura"))
        }
    }

    #[test]
    fn quando_leitura_falha_deve_retornar_erro_de_io() {
        assert!(matches!(
            read_limited(FailingReader, 10),
            Err(LoadError::Io(_))
        ));
    }
}
