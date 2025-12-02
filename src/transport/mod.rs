//! HTTP transport implementations.
//!
//! - HTTP/1.1 via hyper + tokio-boring
//! - HTTP/2 via h2 native (with SETTINGS fingerprinting) or hyper
//! - HTTP/3 via quiche

pub mod connector;
pub mod h1_h2;
pub mod h2_native;
pub mod h3;
