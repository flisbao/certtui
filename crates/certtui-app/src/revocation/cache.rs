//! In-memory revocation cache, bounded by bytes, evicting the least recently used.
//!
//! One cache lives for one execution (spec section 6.3): OCSP verdicts keyed
//! by `(issuer_key_hash, serial)` and CRL bodies keyed by URL. The LRU is
//! hand-rolled (`HashMap` plus a recency queue) to avoid a dependency.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use certtui_domain::model::RevocationStatus;

/// What identifies a cached answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// An OCSP verdict for one certificate of one issuer.
    Ocsp {
        /// SHA-1 of the issuer's public key (the `CertID` key hash).
        issuer_key_hash: Vec<u8>,
        /// Certificate serial, without leading zeros.
        serial: Vec<u8>,
    },
    /// A downloaded CRL body.
    Crl {
        /// The URL it came from.
        url: String,
    },
}

/// The cached value.
#[derive(Clone, PartialEq, Eq)]
pub enum CachedPayload {
    /// A final verdict (OCSP).
    Status(RevocationStatus),
    /// Raw bytes (a CRL, evaluated per certificate).
    Bytes(Vec<u8>),
}

impl std::fmt::Debug for CachedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => f.debug_tuple("Status").field(status).finish(),
            Self::Bytes(bytes) => f.debug_tuple("Bytes").field(&bytes.len()).finish(),
        }
    }
}

/// A cached value and what it costs against the byte budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedItem {
    /// The value.
    pub payload: CachedPayload,
    /// Bytes charged to the cache budget.
    pub size: usize,
}

/// Fixed overhead charged per verdict, on top of its text.
const STATUS_OVERHEAD: usize = 64;

impl CachedItem {
    /// A verdict, charged its text length plus a fixed overhead.
    #[must_use]
    pub fn status(status: RevocationStatus) -> Self {
        let text = match &status {
            RevocationStatus::Good => 0,
            RevocationStatus::Revoked { reason, .. } => reason.as_ref().map_or(0, String::len),
            RevocationStatus::Unknown { why } => why.len(),
        };
        Self {
            size: STATUS_OVERHEAD.saturating_add(text),
            payload: CachedPayload::Status(status),
        }
    }

    /// Raw bytes, charged their length.
    #[must_use]
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self {
            size: bytes.len(),
            payload: CachedPayload::Bytes(bytes),
        }
    }
}

/// Byte-bounded LRU cache.
#[derive(Debug)]
pub struct RevocationCache {
    max_bytes: usize,
    size: usize,
    items: HashMap<CacheKey, Arc<CachedItem>>,
    /// Keys from least recently used (front) to most recently used (back).
    order: VecDeque<CacheKey>,
}

impl RevocationCache {
    /// An empty cache that never holds more than `max_bytes`.
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            size: 0,
            items: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Bytes currently charged.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.size
    }

    /// Number of items held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the cache holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Looks `key` up and marks it the most recently used.
    pub fn get(&mut self, key: &CacheKey) -> Option<Arc<CachedItem>> {
        let item = self.items.get(key).map(Arc::clone)?;
        self.touch(key);
        Some(item)
    }

    /// Stores `item` under `key`, replacing any previous value and evicting
    /// least recently used items until it fits. An item larger than the whole
    /// budget is not stored (and the previous value of `key` is dropped, since
    /// it is now out of date).
    pub fn insert(&mut self, key: CacheKey, item: CachedItem) {
        self.remove(&key);
        if item.size > self.max_bytes {
            return;
        }
        while self.size.saturating_add(item.size) > self.max_bytes {
            let Some(oldest) = self.order.front().cloned() else {
                break;
            };
            self.remove(&oldest);
        }
        self.size = self.size.saturating_add(item.size);
        self.order.push_back(key.clone());
        self.items.insert(key, Arc::new(item));
    }

    fn touch(&mut self, key: &CacheKey) {
        if let Some(pos) = self.order.iter().position(|k| k == key)
            && let Some(k) = self.order.remove(pos)
        {
            self.order.push_back(k);
        }
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(old) = self.items.remove(key) {
            self.size = self.size.saturating_sub(old.size);
            self.order.retain(|k| k != key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(n: u8) -> CacheKey {
        CacheKey::Crl {
            url: format!("http://crl.example/{n}.crl"),
        }
    }

    fn blob(size: usize) -> CachedItem {
        CachedItem::bytes(vec![0; size])
    }

    #[test]
    fn quando_insere_acima_do_teto_deve_evictar_o_menos_recente() {
        let mut cache = RevocationCache::new(100);
        cache.insert(key(1), blob(40));
        cache.insert(key(2), blob(40));
        cache.insert(key(3), blob(40));

        assert!(cache.get(&key(1)).is_none());
        assert!(cache.get(&key(2)).is_some());
        assert!(cache.get(&key(3)).is_some());
        assert_eq!(cache.size_bytes(), 80);
    }

    #[test]
    fn quando_get_deve_promover_para_mais_recente() {
        let mut cache = RevocationCache::new(100);
        cache.insert(key(1), blob(40));
        cache.insert(key(2), blob(40));
        assert!(cache.get(&key(1)).is_some());
        cache.insert(key(3), blob(40));

        assert!(cache.get(&key(2)).is_none(), "2 era o menos recente");
        assert!(cache.get(&key(1)).is_some());
        assert!(cache.get(&key(3)).is_some());
    }

    #[test]
    fn quando_item_maior_que_o_teto_deve_nao_ser_guardado() {
        let mut cache = RevocationCache::new(100);
        cache.insert(key(1), blob(101));

        assert!(cache.is_empty());
        assert_eq!(cache.size_bytes(), 0);
        assert!(cache.get(&key(1)).is_none());
    }

    #[test]
    fn quando_item_grande_substitui_chave_existente_deve_descartar_o_valor_velho() {
        let mut cache = RevocationCache::new(100);
        cache.insert(key(1), blob(10));
        cache.insert(key(1), blob(500));

        assert!(cache.get(&key(1)).is_none());
        assert_eq!(cache.size_bytes(), 0);
    }

    #[test]
    fn quando_chave_repetida_deve_substituir_e_ajustar_tamanho() {
        let mut cache = RevocationCache::new(100);
        cache.insert(key(1), blob(60));
        cache.insert(key(1), blob(10));

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.size_bytes(), 10);
        let got = cache.get(&key(1)).unwrap();
        assert_eq!(got.payload, CachedPayload::Bytes(vec![0; 10]));
    }

    #[test]
    fn quando_item_e_veredito_deve_cobrar_texto_mais_overhead() {
        let item = CachedItem::status(RevocationStatus::Unknown {
            why: "x".repeat(10),
        });
        assert_eq!(item.size, STATUS_OVERHEAD + 10);
        assert_eq!(
            CachedItem::status(RevocationStatus::Good).size,
            STATUS_OVERHEAD
        );
    }

    #[test]
    fn quando_chaves_ocsp_e_crl_tem_o_mesmo_texto_deve_ser_entradas_distintas() {
        let mut cache = RevocationCache::new(1_000);
        let ocsp = CacheKey::Ocsp {
            issuer_key_hash: vec![1],
            serial: vec![2],
        };
        cache.insert(ocsp.clone(), CachedItem::status(RevocationStatus::Good));
        cache.insert(key(1), blob(5));

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&ocsp).is_some());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u8, usize),
        Get(u8),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0_u8..8, 0_usize..400).prop_map(|(k, s)| Op::Insert(k, s)),
            (0_u8..8).prop_map(Op::Get),
        ]
    }

    proptest! {
        #[test]
        fn quando_sequencia_aleatoria_de_ops_deve_nunca_passar_do_teto(
            ops in proptest::collection::vec(op(), 0..200)
        ) {
            const MAX: usize = 500;
            let mut cache = RevocationCache::new(MAX);
            for op in ops {
                match op {
                    Op::Insert(k, size) => cache.insert(key(k), blob(size)),
                    Op::Get(k) => { let _ = cache.get(&key(k)); }
                }
                prop_assert!(cache.size_bytes() <= MAX);
                let sum: usize = cache.items.values().map(|i| i.size).sum();
                prop_assert_eq!(sum, cache.size_bytes());
                prop_assert_eq!(cache.order.len(), cache.items.len());
            }
        }
    }
}
