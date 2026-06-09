//! Container image handling: OCI layer flattening.

pub mod flatten;

pub use flatten::flatten_layers;
