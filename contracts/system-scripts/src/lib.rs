//! Shared helpers for the CKB system scripts rewritten in Rust.
#![no_std]

use ckb_std::ckb_constants::{InputField, Source};
use ckb_std::error::SysError;

/// Maximum size of a witness or script in bytes (same limitation as the
/// original C implementation).
pub const MAX_WITNESS_SIZE: usize = 32768;
pub const SCRIPT_SIZE: usize = 32768;
pub const BLAKE2B_BLOCK_SIZE: usize = 32;
pub const BLAKE160_SIZE: usize = 20;
pub const PUBKEY_SIZE: usize = 33;
pub const SIGNATURE_SIZE: usize = 65;
pub const RECID_INDEX: usize = 64;

/// Calculate the number of input cells in the current transaction following
/// the same probing/binary-search scheme as the original C code.
pub fn calculate_inputs_len() -> usize {
    let mut lo: usize = 0;
    let mut hi: usize = 4;
    loop {
        let mut buf = [0u8; 8];
        match ckb_std::syscalls::load_input_by_field(
            &mut buf,
            0,
            hi,
            Source::Input,
            InputField::Since,
        ) {
            Ok(_) => {
                lo = hi;
                hi = hi.wrapping_mul(2);
            }
            Err(_) => break,
        }
    }

    while lo + 1 != hi {
        let i = (lo + hi) / 2;
        let mut buf = [0u8; 8];
        match ckb_std::syscalls::load_input_by_field(
            &mut buf,
            0,
            i,
            Source::Input,
            InputField::Since,
        ) {
            Ok(_) => lo = i,
            Err(_) => hi = i,
        }
    }

    hi
}

/// Result of checking a since value against all inputs of the current group.
pub enum SinceError {
    /// A syscall returned an unexpected error.
    Syscall,
    /// The since flags of an input did not match the constraint.
    IncorrectFlag,
    /// The since value of an input was smaller than the constraint.
    IncorrectValue,
}

pub const SINCE_VALUE_BITS: u32 = 56;
pub const SINCE_VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
pub const SINCE_EPOCH_FRACTION_FLAG: u64 = 0x20;

/// Compare two epoch numbers with fractions. Returns:
/// 0 when equal, -1 when `a < b`, 1 when `a > b`.
pub fn epoch_number_with_fraction_cmp(a: u64, b: u64) -> i8 {
    const NUMBER_OFFSET: u32 = 0;
    const NUMBER_BITS: u32 = 24;
    const NUMBER_MASK: u64 = (1 << NUMBER_BITS) - 1;
    const INDEX_OFFSET: u32 = NUMBER_BITS;
    const INDEX_BITS: u32 = 16;
    const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
    const LENGTH_OFFSET: u32 = NUMBER_BITS + INDEX_BITS;
    const LENGTH_BITS: u32 = 16;
    const LENGTH_MASK: u64 = (1 << LENGTH_BITS) - 1;

    let a_epoch = (a >> NUMBER_OFFSET) & NUMBER_MASK;
    let a_index = (a >> INDEX_OFFSET) & INDEX_MASK;
    let a_len = (a >> LENGTH_OFFSET) & LENGTH_MASK;

    let b_epoch = (b >> NUMBER_OFFSET) & NUMBER_MASK;
    let b_index = (b >> INDEX_OFFSET) & INDEX_MASK;
    let b_len = (b >> LENGTH_OFFSET) & LENGTH_MASK;

    if a_epoch < b_epoch {
        -1
    } else if a_epoch > b_epoch {
        1
    } else {
        let a_block = a_index * b_len;
        let b_block = b_index * a_len;
        if a_block < b_block {
            -1
        } else if a_block > b_block {
            1
        } else {
            0
        }
    }
}

/// Validate the since value against every input of the current lock group.
pub fn check_since(since: u64) -> Result<(), SinceError> {
    let since_flags = since >> SINCE_VALUE_BITS;
    let since_value = since & SINCE_VALUE_MASK;

    let mut i: usize = 0;
    loop {
        let mut buf = [0u8; 8];
        match ckb_std::syscalls::load_input_by_field(
            &mut buf,
            0,
            i,
            Source::GroupInput,
            InputField::Since,
        ) {
            Ok(8) => {}
            Ok(_) => return Err(SinceError::Syscall),
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(SinceError::Syscall),
        }

        let input_since = u64::from_le_bytes(buf);
        let input_since_flags = input_since >> SINCE_VALUE_BITS;
        let input_since_value = input_since & SINCE_VALUE_MASK;

        if since_flags != input_since_flags {
            return Err(SinceError::IncorrectFlag);
        }
        if input_since_flags == SINCE_EPOCH_FRACTION_FLAG {
            if epoch_number_with_fraction_cmp(input_since_value, since_value) < 0 {
                return Err(SinceError::IncorrectValue);
            }
        } else if input_since_value < since_value {
            return Err(SinceError::IncorrectValue);
        }
        i += 1;
    }

    Ok(())
}

/// Errors that can occur while recovering a pubkey from a recoverable
/// signature.
pub enum SecpError {
    ParseSignature,
    RecoverPubkey,
}

/// Parse a 65-byte compact recoverable signature, recover the public key and
/// return the blake2b (ckb-default-hash) hash of the 33-byte compressed
/// public key.
pub fn recover_pubkey_hash(
    message: &[u8; BLAKE2B_BLOCK_SIZE],
    compact_signature: &[u8; SIGNATURE_SIZE],
) -> Result<[u8; BLAKE2B_BLOCK_SIZE], SecpError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let recovery_id =
        RecoveryId::from_byte(compact_signature[RECID_INDEX]).ok_or(SecpError::ParseSignature)?;
    let signature = Signature::from_slice(&compact_signature[..RECID_INDEX])
        .map_err(|_| SecpError::ParseSignature)?;
    let verifying_key = VerifyingKey::recover_from_prehash(message, &signature, recovery_id)
        .map_err(|_| SecpError::RecoverPubkey)?;

    let encoded = verifying_key.to_sec1_point(true);
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(encoded.as_bytes());
    let mut hash = [0u8; BLAKE2B_BLOCK_SIZE];
    hasher.finalize(&mut hash);
    Ok(hash)
}

/// Program entry point for the on-chain scripts.
///
/// This is the same as `ckb_std::entry!`, except that the `_start` trampoline
/// performs the call through a scratch register (`t0`). `rustc` emits
/// `jalr ra, offset(ra)` for a register-indirect call, and on VM version 0
/// the `jalr` implementation writes the link register *before* reading the
/// source register. With `rd == rs1 == ra`, the addressing register gets
/// clobbered and the call lands 8 bytes too far (an off-by-around-the-link
/// value bug), causing a MemOutOfBound fault. Using `t0` as the address
/// register avoids this.
#[macro_export]
macro_rules! contract_entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn __ckb_std_main(
            argc: core::ffi::c_int,
            argv: *const ckb_std::env::Arg,
        ) -> i8 {
            let argv = core::slice::from_raw_parts(argv, argc as usize);
            unsafe { ckb_std::env::set_argv(argv) };
            $main()
        }

        #[cfg(target_arch = "riscv64")]
        core::arch::global_asm!(
            ".global _start",
            "_start:",
            // argc
            "lw a0, 0(sp)",
            // argv
            "addi a1, sp, 8",
            // envp
            "li a2, 0",
            // Call __ckb_std_main through t0 so the VM version 0 `jalr`
            // implementation cannot clobber the address register (see above).
            ".Lckb_contract_trampoline:",
            "auipc t0, %pcrel_hi(__ckb_std_main)",
            "addi t0, t0, %pcrel_lo(.Lckb_contract_trampoline)",
            "jalr ra, 0(t0)",
            // Exit.
            "li a7, 93",
            "ecall",
        );

        #[cfg(target_arch = "riscv64")]
        #[panic_handler]
        fn panic_handler(_panic_info: &core::panic::PanicInfo) -> ! {
            ckb_std::syscalls::exit(-101)
        }
    };
}

pub fn load_witness_into(buf: &mut [u8], index: usize, source: Source) -> Result<usize, SysError> {
    ckb_std::syscalls::load_witness(buf, 0, index, source)
}

/// Load the tx hash of the current transaction.
pub fn load_tx_hash() -> Result<[u8; BLAKE2B_BLOCK_SIZE], SysError> {
    let mut buf = [0u8; BLAKE2B_BLOCK_SIZE];
    let len = ckb_std::syscalls::load_tx_hash(&mut buf, 0)?;
    if len != BLAKE2B_BLOCK_SIZE {
        return Err(SysError::Unknown(0));
    }
    Ok(buf)
}
