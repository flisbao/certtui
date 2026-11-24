//! Bounded readers used by local source adapters.

mod bounded;

// Justificativa: a porta que consumirá esta função será adicionada no Task 15.
#[allow(unused_imports)]
pub(crate) use bounded::read_limited;
