check:
    cargo fmt
    cargo clippy -- -D warnings

example name:
    cargo run -p rust-examples --example {{name}}
