check:
    cargo fmt
    cargo clippy -- -D warnings

example name:
    cargo run -p rust-examples --example {{name}}

build-wasm out:
    cargo build -p bepeefe-wasm --target wasm32-unknown-unknown -r
    wasm-bindgen --target web --out-dir {{out}} target/wasm32-unknown-unknown/release/bepeefe_wasm.wasm
