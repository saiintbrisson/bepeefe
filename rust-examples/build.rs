#![allow(clippy::disallowed_macros)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("TARGET").unwrap().contains("bpf") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("bpf_target");

    let status = Command::new("cargo")
        .args([
            "build",
            "--examples",
            "--release",
            "-Z",
            "build-std=core,alloc",
            "--target",
            "bpfel-unknown-none",
        ])
        .env(
            "RUSTFLAGS",
            r#"-C debuginfo=2 -C linker=bpf-linker -C link-arg=--btf -C link-arg=--disable-memory-builtins"#,
        )
        .env("CARGO_TARGET_DIR", &target_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .current_dir(&manifest_dir)
        .status()
        .expect("failed to build BPF program");

    assert!(status.success(), "BPF build failed");

    let bpf_out = target_dir.join("bpfel-unknown-none/release/examples");
    println!("cargo:rustc-env=BPF_OUT_DIR={}", bpf_out.display());
    println!("cargo:rerun-if-changed=lib.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
