//! HTTP transport implementations.
//!
//! - HTTP/1.1 and HTTP/2 via hyper + tokio-boring
//! - HTTP/3 via quiche

pub mod connector;
pub mod h1_h2;
pub mod h3;
