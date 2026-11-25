//! Domain layer: pure certificate types and rules, no I/O.

pub mod batch_input;

pub mod batch_row;

pub mod chain_analysis;

pub mod error;

pub mod extract;

pub mod finding;

pub mod limits;

pub mod lint;

pub mod model;

pub mod sanitize;

pub mod target;

pub mod target_parse;

pub mod time;
