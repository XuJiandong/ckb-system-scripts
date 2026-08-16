//! secp256k1_blake160_sighash_all lock script, ported from C to Rust.
#![no_std]
#![no_main]

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::{
    packed::{ScriptReader, WitnessArgsReader},
    prelude::*,
};
use ckb_std::error::SysError;
use system_scripts::{
    calculate_inputs_len, load_tx_hash, recover_pubkey_hash, BLAKE160_SIZE, SCRIPT_SIZE,
    SIGNATURE_SIZE,
};

system_scripts::contract_entry!(program_entry);
ckb_std::default_alloc!();

// Error codes, kept identical to the original C implementation.
const ERROR_ARGUMENTS_LEN: i8 = -1;
const ERROR_ENCODING: i8 = -2;
const ERROR_SYSCALL: i8 = -3;
const ERROR_SECP_RECOVER_PUBKEY: i8 = -11;
const ERROR_SECP_PARSE_SIGNATURE: i8 = -14;
const ERROR_SCRIPT_TOO_LONG: i8 = -21;
const ERROR_WITNESS_SIZE: i8 = -22;
const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;

const MAX_WITNESS_SIZE: usize = 32768;

pub fn program_entry() -> i8 {
    // Load and extract the script args (20-byte blake160 hash of pubkey).
    let mut script = [0u8; SCRIPT_SIZE];
    let script_len = match ckb_std::syscalls::load_script(&mut script, 0) {
        Ok(len) => len,
        Err(SysError::LengthNotEnough(_)) => return ERROR_SCRIPT_TOO_LONG,
        Err(_) => return ERROR_SYSCALL,
    };
    if ScriptReader::verify(&script[..script_len], false).is_err() {
        return ERROR_ENCODING;
    }
    let script_reader = ScriptReader::new_unchecked(&script[..script_len]);
    let args = script_reader.args().raw_data();
    if args.len() != BLAKE160_SIZE {
        return ERROR_ARGUMENTS_LEN;
    }

    // Load the first witness of the current lock group.
    let mut witness = [0u8; MAX_WITNESS_SIZE];
    let witness_len = match ckb_std::syscalls::load_witness(&mut witness, 0, 0, Source::GroupInput)
    {
        Ok(len) => len,
        Err(SysError::LengthNotEnough(_)) => return ERROR_WITNESS_SIZE,
        Err(_) => return ERROR_SYSCALL,
    };

    // Extract the lock field (must be a 65-byte recoverable signature).
    if WitnessArgsReader::verify(&witness[..witness_len], false).is_err() {
        return ERROR_ENCODING;
    }
    let witness_reader = WitnessArgsReader::new_unchecked(&witness[..witness_len]);
    let lock_opt = witness_reader.lock().to_opt();
    let lock = match lock_opt {
        Some(lock) if lock.len() == SIGNATURE_SIZE => lock,
        None => return ERROR_ENCODING,
        Some(_) => return ERROR_ARGUMENTS_LEN,
    };
    let lock_raw = lock.raw_data();
    let lock_offset = (lock_raw.as_ptr() as usize) - (witness.as_ptr() as usize);
    let mut signature = [0u8; SIGNATURE_SIZE];
    signature.copy_from_slice(&witness[lock_offset..lock_offset + SIGNATURE_SIZE]);

    // Load the current transaction hash.
    let tx_hash = match load_tx_hash() {
        Ok(hash) => hash,
        Err(_) => return ERROR_SYSCALL,
    };

    // Prepare the signing message:
    // 1. transaction hash
    // 2. witness length + first witness with a zeroed lock field
    // 3. remaining group witnesses
    // 4. witnesses whose indices exceed the input count
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&tx_hash);

    let zero_sig = [0u8; SIGNATURE_SIZE];
    hasher.update(&(witness_len as u64).to_le_bytes());
    hasher.update(&witness[..lock_offset]);
    hasher.update(&zero_sig);
    hasher.update(&witness[lock_offset + SIGNATURE_SIZE..witness_len]);

    let mut i: usize = 1;
    loop {
        let mut buf = [0u8; MAX_WITNESS_SIZE];
        match ckb_std::syscalls::load_witness(&mut buf, 0, i, Source::GroupInput) {
            Ok(len) => {
                hasher.update(&(len as u64).to_le_bytes());
                hasher.update(&buf[..len]);
            }
            Err(SysError::LengthNotEnough(_)) => return ERROR_WITNESS_SIZE,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return ERROR_SYSCALL,
        }
        i += 1;
    }

    i = calculate_inputs_len();
    loop {
        let mut buf = [0u8; MAX_WITNESS_SIZE];
        match ckb_std::syscalls::load_witness(&mut buf, 0, i, Source::Input) {
            Ok(len) => {
                hasher.update(&(len as u64).to_le_bytes());
                hasher.update(&buf[..len]);
            }
            Err(SysError::LengthNotEnough(_)) => return ERROR_WITNESS_SIZE,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return ERROR_SYSCALL,
        }
        i += 1;
    }

    let mut message = [0u8; 32];
    hasher.finalize(&mut message);

    // Recover the public key from the signature and check the blake160 hash.
    let pubkey_hash = match recover_pubkey_hash(&message, &signature) {
        Ok(hash) => hash,
        Err(system_scripts::SecpError::ParseSignature) => return ERROR_SECP_PARSE_SIGNATURE,
        Err(system_scripts::SecpError::RecoverPubkey) => return ERROR_SECP_RECOVER_PUBKEY,
    };

    if &pubkey_hash[..BLAKE160_SIZE] != args {
        return ERROR_PUBKEY_BLAKE160_HASH;
    }

    0
}
