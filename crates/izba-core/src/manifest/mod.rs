//! Project manifest (`izba.yml`): schema, canonical form, structural diff, and
//! the host-only review/base store backing `izba diff`/`promote`/`export`.

pub mod apply;
pub mod diff;
pub mod normalize;
pub mod quantity;
pub mod schema;
pub mod store;

pub use diff::{classify, diff as diff_normalized, DriftState, FieldClass, FieldDelta};
pub use normalize::{ImageSource, Normalized};
pub use schema::Manifest;
