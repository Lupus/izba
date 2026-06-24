//! In-VM build pipeline: BuildKit orchestration, builder-image management,
//! and build-network policy integration.

pub mod builder_image;
pub mod script;

pub use builder_image::{ensure_builder_image, BUILDER_IMAGE_REF};
pub use script::build_script;
