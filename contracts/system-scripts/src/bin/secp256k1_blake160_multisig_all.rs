//! secp256k1_blake160_multisig_all lock script, ported from C to Rust.
#![no_std]
#![no_main]

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::{
    packed::{ScriptReader, WitnessArgsReader},
    prelude::*,
};
use ckb_std::error::SysError;
use system_scripts::{
    calculate_inputs_len, check_since, load_tx_hash, recover_pubkey_hash, SinceError,
    BLAKE160_SIZE, SCRIPT_SIZE, SIGNATURE_SIZE,
};

system_scripts::contract_entry!(program_entry);
ckb_std::default_alloc!();

// Script args validation errors.
const ERROR_INVALID_RESERVE_FIELD: i8 = -41;
const ERROR_INVALID_PUBKEYS_CNT: i8 = -42;
const ERROR_INVALID_THRESHOLD: i8 = -43;
const ERROR_INVALID_REQUIRE_FIRST_N: i8 = -44;
// Multi-signing validation errors.
const ERROR_MULTSIG_SCRIPT_HASH: i8 = -51;
const ERROR_VERIFICATION: i8 = -52;
// Common errors.
const ERROR_ARGUMENTS_LEN: i8 = -1;
const ERROR_ENCODING: i8 = -2;
const ERROR_SYSCALL: i8 = -3;
const ERROR_SECP_RECOVER_PUBKEY: i8 = -11;
const ERROR_SECP_PARSE_SIGNATURE: i8 = -14;
const ERROR_SCRIPT_TOO_LONG: i8 = -21;
const ERROR_WITNESS_SIZE: i8 = -22;
const ERROR_INCORRECT_SINCE_FLAGS: i8 = -23;
const ERROR_INCORRECT_SINCE_VALUE: i8 = -24;

const MAX_WITNESS_SIZE: usize = 32768;
const FLAGS_SIZE: usize = 4;

pub fn program_entry() -> i8 {
    // Load the current script.
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
    if args.len() != BLAKE160_SIZE && args.len() != BLAKE160_SIZE + 8 {
        return ERROR_ARGUMENTS_LEN;
    }

    // Extract optional since value.
    if args.len() == BLAKE160_SIZE + 8 {
        let since = u64::from_le_bytes(args[BLAKE160_SIZE..BLAKE160_SIZE + 8].try_into().unwrap());
        match check_since(since) {
            Ok(()) => {}
            Err(SinceError::Syscall) => return ERROR_SYSCALL,
            Err(SinceError::IncorrectFlag) => return ERROR_INCORRECT_SINCE_FLAGS,
            Err(SinceError::IncorrectValue) => return ERROR_INCORRECT_SINCE_VALUE,
        }
    }

    // Load the first witness of the current lock group.
    let mut witness = [0u8; MAX_WITNESS_SIZE];
    let witness_len = match ckb_std::syscalls::load_witness(&mut witness, 0, 0, Source::GroupInput)
    {
        Ok(len) => len,
        Err(SysError::LengthNotEnough(_)) => return ERROR_WITNESS_SIZE,
        Err(_) => return ERROR_SYSCALL,
    };

    if WitnessArgsReader::verify(&witness[..witness_len], false).is_err() {
        return ERROR_ENCODING;
    }
    let witness_reader = WitnessArgsReader::new_unchecked(&witness[..witness_len]);
    let lock = match witness_reader.lock().to_opt() {
        Some(lock) => lock,
        None => return ERROR_ENCODING,
    };
    let lock_raw = lock.raw_data();
    let lock_len = lock_raw.len();
    let lock_offset = (lock_raw.as_ptr() as usize) - (witness.as_ptr() as usize);

    if lock_len < FLAGS_SIZE {
        return ERROR_WITNESS_SIZE;
    }
    // Safety guard mirroring the C code.
    if lock_len > witness_len {
        return ERROR_ENCODING;
    }

    let flags: [u8; FLAGS_SIZE] = lock_raw[..FLAGS_SIZE].try_into().unwrap();
    let reserved_field = flags[0];
    let require_first_n = flags[1];
    let threshold = flags[2];
    let pubkeys_cnt = flags[3];

    if reserved_field != 0 {
        return ERROR_INVALID_RESERVE_FIELD;
    }
    if pubkeys_cnt == 0 {
        return ERROR_INVALID_PUBKEYS_CNT;
    }
    if threshold > pubkeys_cnt {
        return ERROR_INVALID_THRESHOLD;
    }
    if threshold == 0 {
        return ERROR_INVALID_THRESHOLD;
    }
    if require_first_n > threshold {
        return ERROR_INVALID_REQUIRE_FIRST_N;
    }

    let multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * (pubkeys_cnt as usize);
    let signatures_len = SIGNATURE_SIZE * (threshold as usize);
    let required_lock_len = multisig_script_len + signatures_len;
    if lock_len != required_lock_len {
        return ERROR_WITNESS_SIZE;
    }

    // Hash check of the multisig script part.
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&lock_raw[..multisig_script_len]);
    let mut multisig_script_hash = [0u8; 32];
    hasher.finalize(&mut multisig_script_hash);
    if &multisig_script_hash[..BLAKE160_SIZE] != &args[..BLAKE160_SIZE] {
        return ERROR_MULTSIG_SCRIPT_HASH;
    }

    // Load the current transaction hash.
    let tx_hash = match load_tx_hash() {
        Ok(hash) => hash,
        Err(_) => return ERROR_SYSCALL,
    };

    // Prepare the signing message, zeroing the signature portion of the
    // first witness.
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&tx_hash);
    hasher.update(&(witness_len as u64).to_le_bytes());
    hasher.update(&witness[..lock_offset]);
    hasher.update(&lock_raw[..multisig_script_len]);
    for _ in 0..signatures_len {
        hasher.update(&[0u8; 1]);
    }
    hasher.update(&witness[lock_offset + required_lock_len..witness_len]);

    // Hash remaining group witnesses.
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

    // Hash witnesses whose indices exceed the input count.
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

    // Verify `threshold` signatures.
    let mut used_signatures = [0u8; 255];
    for sig_i in 0..(threshold as usize) {
        let signature_offset = multisig_script_len + sig_i * SIGNATURE_SIZE;
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&lock_raw[signature_offset..signature_offset + SIGNATURE_SIZE]);

        let pubkey_hash = match recover_pubkey_hash(&message, &signature) {
            Ok(hash) => hash,
            Err(system_scripts::SecpError::ParseSignature) => return ERROR_SECP_PARSE_SIGNATURE,
            Err(system_scripts::SecpError::RecoverPubkey) => return ERROR_SECP_RECOVER_PUBKEY,
        };

        let mut matched = false;
        for used_i in 0..(pubkeys_cnt as usize) {
            if used_signatures[used_i] != 0 {
                continue;
            }
            let pk_offset = FLAGS_SIZE + used_i * BLAKE160_SIZE;
            if &lock_raw[pk_offset..pk_offset + BLAKE160_SIZE] != &pubkey_hash[..BLAKE160_SIZE] {
                continue;
            }
            matched = true;
            used_signatures[used_i] = 1;
            break;
        }

        if !matched {
            return ERROR_VERIFICATION;
        }
    }

    // Enforce the first `require_first_n` public keys.
    for used_i in 0..(require_first_n as usize) {
        if used_signatures[used_i] != 1 {
            return ERROR_VERIFICATION;
        }
    }

    0
}
