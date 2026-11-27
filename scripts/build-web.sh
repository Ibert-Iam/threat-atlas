#!/bin/sh
# AtlasSOC web page (ibert.se/AtlasSOC): builds the shared core as WebAssembly next to the page files.
# Output: atlassoc.wasm next to the page files in web/AtlasSOC/. Upload that folder as is (see web/README.md).
set -eu
cd "$(dirname "$0")/.."
rustup target list --installed | grep -q '^wasm32-unknown-unknown$' || rustup target add wasm32-unknown-unknown
cargo build --locked --release -p threat-atlas-web --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/threat_atlas_web.wasm web/AtlasSOC/atlassoc.wasm
shasum -a 256 web/AtlasSOC/*
