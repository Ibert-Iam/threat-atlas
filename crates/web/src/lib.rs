//! The AtlasSOC web page's WebAssembly module: the shared core's `web` entry points, built as a `.wasm` file.
//! Build: `cargo build -p threat-atlas-web --release --target wasm32-unknown-unknown`. Native builds compile
//! this crate as an empty library.
#[cfg(target_arch = "wasm32")]
pub use threat_atlas_core::web::*;
