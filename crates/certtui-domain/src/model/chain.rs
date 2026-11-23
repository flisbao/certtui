//! An ordered list of certificates, bounded by `Limits::max_chain_len`.

use crate::error::ChainError;
use crate::limits::Limits;
use crate::model::CertificateRecord;

/// Certificates in the order they were obtained (leaf first when presented
/// by a server). The length is validated at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain(Vec<CertificateRecord>);

impl Chain {
    /// Builds a chain, rejecting more than `limits.max_chain_len` records.
    ///
    /// # Errors
    ///
    /// [`ChainError::TooLong`] when `records` is longer than the limit.
    pub fn new(records: Vec<CertificateRecord>, limits: &Limits) -> Result<Chain, ChainError> {
        if records.len() > limits.max_chain_len {
            return Err(ChainError::TooLong {
                len: records.len(),
                max: limits.max_chain_len,
            });
        }
        Ok(Chain(records))
    }

    /// The records, in order.
    #[must_use]
    pub fn records(&self) -> &[CertificateRecord] {
        &self.0
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the chain has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The record at position `i`, if any.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&CertificateRecord> {
        self.0.get(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ChainError;
    use crate::limits::Limits;
    use crate::model::{CertOrigin, CertificateRecord};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn record(position: usize) -> CertificateRecord {
        let der = std::fs::read(format!("{FIXTURES}/rsa2048-leaf.der")).unwrap();
        CertificateRecord::from_der(&der, CertOrigin::Presented { position }, &Limits::default())
            .unwrap()
    }

    #[test]
    fn quando_chain_excede_max_chain_len_deve_dar_too_long() {
        let limits = Limits::default();
        let records: Vec<_> = (0..=limits.max_chain_len).map(record).collect();
        let err = Chain::new(records, &limits).unwrap_err();
        assert_eq!(
            err,
            ChainError::TooLong {
                len: limits.max_chain_len + 1,
                max: limits.max_chain_len
            }
        );
    }

    #[test]
    fn quando_chain_no_limite_deve_aceitar_e_expor_registros() {
        let limits = Limits::default();
        let records: Vec<_> = (0..limits.max_chain_len).map(record).collect();
        let chain = Chain::new(records, &limits).unwrap();
        assert_eq!(chain.len(), limits.max_chain_len);
        assert!(!chain.is_empty());
        assert_eq!(chain.records().len(), limits.max_chain_len);
        assert!(chain.get(0).is_some());
        assert!(chain.get(limits.max_chain_len).is_none());
    }

    #[test]
    fn quando_chain_vazia_deve_ser_valida() {
        let chain = Chain::new(Vec::new(), &Limits::default()).unwrap();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }
}
