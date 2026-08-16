pub use blake2b_rs::{Blake2b, Blake2bBuilder};
use includedir_codegen::Compression;

use std::{
    env,
    fs::File,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

const PATH_PREFIX: &str = "specs/cells/";
const BUF_SIZE: usize = 8 * 1024;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

const BINARIES: &[(&str, &str)] = &[
    (
        "secp256k1_blake160_sighash_all",
        "d034a161243a194681d8fcaeda5a2de86973657b2e1133cd9f262098d1247565",
    ),
    (
        "secp256k1_data",
        "9799bee251b975b82c45a02154ce28cec89c5853ecc14d12b7b8cccfc19e0af4",
    ),
    (
        "dao",
        "56987176480e88cf8600d9efe1a4677fd3d560c5edde2ad39dbc8fbc2d1c541a",
    ),
    (
        "secp256k1_blake160_multisig_all",
        "f38d5067fa938b5d8763abadba01447a84932dae91b3b301ddbe69c70b450281",
    ),
];

/// The on-chain scripts are now written in Rust and live in
/// `contracts/system-scripts`. Compile them for the RISC-V target and place
/// the resulting ELF files where the rest of this crate (and the test suite)
/// expect them.
fn build_contracts() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let contract_pkg = "ckb-system-scripts-contract";
    let target = "riscv64imac-unknown-none-elf";
    let contract_target_dir = manifest_dir.join("target").join("contract-build");
    let contract_bin_dir = contract_target_dir.join(target).join("release");

    let scripts = [
        "secp256k1_blake160_sighash_all",
        "secp256k1_blake160_multisig_all",
        "dao",
    ];

    let needs_build = scripts.iter().any(|name| {
        let dest = manifest_dir.join(PATH_PREFIX).join(name);
        let src = manifest_dir
            .join("contracts/system-scripts/src/bin")
            .join(format!("{}.rs", name));
        let lib = manifest_dir.join("contracts/system-scripts/src/lib.rs");
        let toml = manifest_dir.join("contracts/system-scripts/Cargo.toml");
        !dest.exists()
            || !src.exists()
            || src.metadata().map(|m| m.modified().unwrap()).ok()
                > dest.metadata().map(|m| m.modified().unwrap()).ok()
            || lib.metadata().map(|m| m.modified().unwrap()).ok()
                > dest.metadata().map(|m| m.modified().unwrap()).ok()
            || toml.metadata().map(|m| m.modified().unwrap()).ok()
                > dest.metadata().map(|m| m.modified().unwrap()).ok()
    });

    if !needs_build {
        return;
    }

    // Use a dedicated target directory: the outer cargo process already holds
    // the lock on the default target directory.
    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(&[
            "build",
            "--manifest-path",
            manifest_dir.join("Cargo.toml").to_str().unwrap(),
            "-p",
            contract_pkg,
            "--target",
            target,
            "--release",
        ])
        .env("CARGO_TARGET_DIR", &contract_target_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env(
            "RUSTFLAGS",
            "-C link-arg=-z -C link-arg=separate-code -C target-feature=+relax",
        )
        .status()
        .expect("failed to run cargo build for contracts");

    if !status.success() {
        panic!(
            "failed to build {} for {}; make sure the target is installed: \
             rustup target add {}",
            contract_pkg, target, target
        );
    }

    let specs_cells = manifest_dir.join(PATH_PREFIX);
    std::fs::create_dir_all(&specs_cells).expect("create specs/cells");
    for name in &scripts {
        let from = contract_bin_dir.join(name);
        let to = specs_cells.join(name);
        std::fs::copy(&from, &to).unwrap_or_else(|e| {
            panic!("copy {:?} -> {:?}: {}", from, to, e);
        });
    }
}

fn main() {
    build_contracts();

    let mut bundled = includedir_codegen::start("BUNDLED_CELL");

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("code_hashes.rs");
    let mut out_file = BufWriter::new(File::create(&out_path).expect("create code_hashes.rs"));

    let mut errors = Vec::new();

    for (name, expected_hash) in BINARIES {
        let path = format!("{}{}", PATH_PREFIX, name);

        let mut buf = [0u8; BUF_SIZE];
        bundled
            .add_file(&path, Compression::Gzip)
            .expect("add files to resource bundle");

        // build hash
        let mut blake2b = new_blake2b();
        let mut fd = File::open(&path).expect("open file");
        loop {
            let read_bytes = fd.read(&mut buf).expect("read file");
            if read_bytes > 0 {
                blake2b.update(&buf[..read_bytes]);
            } else {
                break;
            }
        }

        let mut hash = [0u8; 32];
        blake2b.finalize(&mut hash);

        let actual_hash = faster_hex::hex_string(&hash);
        if expected_hash != &actual_hash {
            eprintln!(
                "warning: {} code hash does not match the recorded one: expect {}, actual {}",
                name, expected_hash, actual_hash
            );
            errors.push((name, expected_hash, actual_hash));
        }

        writeln!(
            &mut out_file,
            "pub const CODE_HASH_{}: [u8; 32] = {:?};",
            name.to_uppercase(),
            hash
        )
        .expect("write to code_hashes.rs");
    }

    let _ = errors;

    bundled.build("bundled.rs").expect("build resource bundle");
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}
