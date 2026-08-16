//! Nervos DAO type script, ported from C to Rust.
#![no_std]
#![no_main]

use ckb_std::ckb_constants::{CellField, InputField, Source};
use ckb_std::ckb_types::{
    packed::{HeaderReader, ScriptReader, WitnessArgsReader},
    prelude::*,
};
use ckb_std::error::SysError;

system_scripts::contract_entry!(program_entry);
ckb_std::default_alloc!();

// Error definitions, kept identical to the original C implementation.
const ERROR_WRONG_NUMBER_OF_ARGUMENTS: i8 = -2;
const ERROR_SYSCALL: i8 = -4;
const ERROR_BUFFER_NOT_ENOUGH: i8 = -10;
const ERROR_ENCODING: i8 = -11;
const ERROR_WITNESS_TOO_LONG: i8 = -12;
const ERROR_OVERFLOW: i8 = -13;
const ERROR_INVALID_WITHDRAW_BLOCK: i8 = -14;
const ERROR_INCORRECT_CAPACITY: i8 = -15;
const ERROR_INCORRECT_EPOCH: i8 = -16;
const ERROR_INCORRECT_SINCE: i8 = -17;
const ERROR_NEWLY_CREATED_CELL: i8 = -19;
const ERROR_INVALID_WITHDRAWING_CELL: i8 = -20;
const ERROR_SCRIPT_TOO_LONG: i8 = -21;
const ERROR_MARKER_EXHAUSTED: i8 = -30;

const HASH_SIZE: usize = 32;
const HEADER_SIZE: usize = 4096;
const MAX_WITNESS_SIZE: usize = 32768;
const SCRIPT_SIZE: usize = 32768;

const LOCK_PERIOD_EPOCHS: u64 = 180;

fn raw_load_error(err: ckb_std::error::SysError) -> i8 {
    use ckb_std::error::SysError as E;
    match err {
        E::IndexOutOfBound => 1,
        E::ItemMissing => 2,
        _ => ERROR_SYSCALL,
    }
}

/// 128-bit / 64-bit unsigned division, implemented with plain shift/subtract
/// operations so that no `compiler_builtins` `u128` division helper is linked
/// in. The `auipc ra + jalr ra` sequence emitted for such a helper is
/// misdecoded on CKB VM version 0 (the link register is written before the
/// address register is read when `rd == rs1`).
fn udiv128(numerator: u128, divisor: u64) -> u64 {
    debug_assert!(divisor != 0);
    let mut remainder: u128 = 0;
    let mut quotient: u64 = 0;
    for bit_index in (0..128).rev() {
        remainder = (remainder << 1) | ((numerator >> bit_index) & 1);
        if remainder >= divisor as u128 {
            remainder -= divisor as u128;
            quotient |= 1 << bit_index;
        }
    }
    quotient
}

struct DaoHeaderData {
    block_number: u64,
    epoch_number: u64,
    epoch_index: u64,
    epoch_length: u64,
    dao: [u8; 32],
}

fn extract_epoch_info(epoch: u64, allow_zero_epoch_length: bool) -> Result<(u64, u64, u64), i8> {
    let mut index = (epoch >> 24) & 0xffff;
    let mut length = (epoch >> 40) & 0xffff;
    if length == 0 {
        if allow_zero_epoch_length {
            index = 0;
            length = 1;
        } else {
            return Err(ERROR_INCORRECT_EPOCH);
        }
    }
    if index >= length {
        return Err(ERROR_INCORRECT_EPOCH);
    }
    let number = (epoch >> 0) & 0x00ff_ffff;
    Ok((number, index, length))
}

fn load_dao_header_data(index: usize, source: Source) -> Result<DaoHeaderData, i8> {
    let mut buffer = [0u8; HEADER_SIZE];
    match ckb_std::syscalls::load_header(&mut buffer, 0, index, source) {
        Ok(len) if len <= HEADER_SIZE => {
            if HeaderReader::verify(&buffer[..len], false).is_err() {
                return Err(ERROR_ENCODING);
            }
            let reader = HeaderReader::new_unchecked(&buffer[..len]);
            let raw = reader.raw();
            let dao = raw.dao().raw_data();
            let epoch = u64::from_le_bytes(raw.epoch().raw_data().try_into().unwrap());
            let block_number = u64::from_le_bytes(raw.number().raw_data().try_into().unwrap());

            let (epoch_number, epoch_index, epoch_length) = extract_epoch_info(epoch, false)?;
            let mut dao_arr = [0u8; 32];
            dao_arr.copy_from_slice(&dao[..32]);
            Ok(DaoHeaderData {
                block_number,
                epoch_number,
                epoch_index,
                epoch_length,
                dao: dao_arr,
            })
        }
        Ok(_) => Err(ERROR_BUFFER_NOT_ENOUGH),
        Err(SysError::IndexOutOfBound) => Err(1),
        Err(SysError::ItemMissing) => Err(2),
        Err(_) => Err(ERROR_SYSCALL),
    }
}

fn extract_deposit_header_index(input_index: usize) -> Result<usize, i8> {
    let mut witness = [0u8; MAX_WITNESS_SIZE];
    let witness_len =
        match ckb_std::syscalls::load_witness(&mut witness, 0, input_index, Source::Input) {
            Ok(len) if len <= MAX_WITNESS_SIZE => len,
            Ok(_) | Err(SysError::LengthNotEnough(_)) => return Err(ERROR_WITNESS_TOO_LONG),
            Err(_) => return Err(ERROR_SYSCALL),
        };

    if WitnessArgsReader::verify(&witness[..witness_len], false).is_err() {
        return Err(ERROR_ENCODING);
    }
    let reader = WitnessArgsReader::new_unchecked(&witness[..witness_len]);
    match reader.input_type().to_opt() {
        Some(bytes) if bytes.len() == 8 => {
            Ok(u64::from_le_bytes(bytes.raw_data().try_into().unwrap()) as usize)
        }
        None => Err(ERROR_ENCODING),
        Some(_) => Err(ERROR_ENCODING),
    }
}

fn calculate_dao_input_capacity(
    input_index: usize,
    deposited_block_number: u64,
    original_capacity: u64,
) -> Result<u64, i8> {
    let deposit_index = extract_deposit_header_index(input_index)?;

    let deposit_data = load_dao_header_data(deposit_index, Source::HeaderDep)?;
    if deposited_block_number != deposit_data.block_number {
        return Err(ERROR_INVALID_WITHDRAW_BLOCK);
    }

    let withdraw_data = load_dao_header_data(input_index, Source::Input)?;

    let withdraw_fraction = withdraw_data.epoch_index * deposit_data.epoch_length;
    let deposit_fraction = deposit_data.epoch_index * withdraw_data.epoch_length;
    // Withdraw header must be after deposit header.
    if (withdraw_data.epoch_number < deposit_data.epoch_number)
        || ((withdraw_data.epoch_number == deposit_data.epoch_number)
            && (withdraw_fraction <= deposit_fraction))
    {
        return Err(ERROR_INVALID_WITHDRAW_BLOCK);
    }

    let mut deposited_epochs = withdraw_data.epoch_number - deposit_data.epoch_number;
    if withdraw_fraction > deposit_fraction {
        deposited_epochs += 1;
    }
    let lock_epochs =
        (deposited_epochs + (LOCK_PERIOD_EPOCHS - 1)) / LOCK_PERIOD_EPOCHS * LOCK_PERIOD_EPOCHS;
    if lock_epochs < LOCK_PERIOD_EPOCHS {
        return Err(ERROR_INVALID_WITHDRAW_BLOCK);
    }

    let minimal_since_epoch_number = deposit_data.epoch_number + lock_epochs;
    let minimal_since_epoch_index = deposit_data.epoch_index;
    let minimal_since_epoch_length = deposit_data.epoch_length;

    // Load the since value of the current input.
    let mut since_buf = [0u8; 8];
    match ckb_std::syscalls::load_input_by_field(
        &mut since_buf,
        0,
        input_index,
        Source::Input,
        InputField::Since,
    ) {
        Ok(8) => {}
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(_) => return Err(ERROR_SYSCALL),
    }
    let input_since = u64::from_le_bytes(since_buf);
    if input_since >> 56 != 0x20 {
        return Err(ERROR_INCORRECT_SINCE);
    }
    let (input_since_epoch_number, input_since_epoch_index, input_since_epoch_length) =
        extract_epoch_info(input_since, true)?;

    let minimal_since_epoch_fraction = minimal_since_epoch_index * input_since_epoch_length;
    let input_since_epoch_fraction = input_since_epoch_index * minimal_since_epoch_length;
    if (input_since_epoch_number < minimal_since_epoch_number)
        || ((input_since_epoch_number == minimal_since_epoch_number)
            && (input_since_epoch_fraction < minimal_since_epoch_fraction))
    {
        return Err(ERROR_INCORRECT_SINCE);
    }

    let deposit_accumulate_rate = u64::from_le_bytes(deposit_data.dao[8..16].try_into().unwrap());
    let withdraw_accumulate_rate = u64::from_le_bytes(withdraw_data.dao[8..16].try_into().unwrap());

    // Occupied capacity.
    let mut occupied_capacity_buf = [0u8; 8];
    match ckb_std::syscalls::load_cell_by_field(
        &mut occupied_capacity_buf,
        0,
        input_index,
        Source::Input,
        CellField::OccupiedCapacity,
    ) {
        Ok(8) => {}
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(_) => return Err(ERROR_SYSCALL),
    }
    let occupied_capacity = u64::from_le_bytes(occupied_capacity_buf);

    let counted_capacity = match original_capacity.checked_sub(occupied_capacity) {
        Some(v) => v,
        None => return Err(ERROR_OVERFLOW),
    };

    let numerator = (counted_capacity as u128) * (withdraw_accumulate_rate as u128);
    let withdraw_counted_capacity = udiv128(numerator, deposit_accumulate_rate);
    let withdraw_capacity = occupied_capacity
        .checked_add(withdraw_counted_capacity)
        .ok_or(ERROR_OVERFLOW)?;

    Ok(withdraw_capacity)
}

fn validate_withdrawing_cell(
    index: usize,
    input_capacity: u64,
    dao_script_hash: &[u8; HASH_SIZE],
) -> Result<(), i8> {
    // Check type script hash.
    let mut type_hash = [0u8; HASH_SIZE];
    match ckb_std::syscalls::load_cell_by_field(
        &mut type_hash,
        0,
        index,
        Source::Output,
        CellField::TypeHash,
    ) {
        Ok(HASH_SIZE) => {}
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(err) => return Err(raw_load_error(err)),
    }
    if &type_hash != dao_script_hash {
        return Err(ERROR_INVALID_WITHDRAWING_CELL);
    }

    // Check capacity.
    let mut output_capacity_buf = [0u8; 8];
    match ckb_std::syscalls::load_cell_by_field(
        &mut output_capacity_buf,
        0,
        index,
        Source::Output,
        CellField::Capacity,
    ) {
        Ok(8) => {}
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(err) => return Err(raw_load_error(err)),
    }
    let output_capacity = u64::from_le_bytes(output_capacity_buf);
    if output_capacity != input_capacity {
        return Err(ERROR_INVALID_WITHDRAWING_CELL);
    }

    // Check cell data (stored deposited block number).
    let deposit_header = load_dao_header_data(index, Source::Input)?;
    let mut stored_block_number_buf = [0u8; 8];
    match ckb_std::syscalls::load_cell_data(&mut stored_block_number_buf, 0, index, Source::Output)
    {
        Ok(8) => {}
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(err) => return Err(raw_load_error(err)),
    }
    let stored_block_number = u64::from_le_bytes(stored_block_number_buf);
    if stored_block_number != deposit_header.block_number {
        return Err(ERROR_INVALID_WITHDRAWING_CELL);
    }

    Ok(())
}

fn validate_input(
    index: usize,
    input_capacities: &mut u64,
    output_withdrawing: &mut bool,
    script_hash: &[u8; HASH_SIZE],
) -> Result<(), i8> {
    let dao_input;
    let mut capacity_buf = [0u8; 8];
    match ckb_std::syscalls::load_cell_by_field(
        &mut capacity_buf,
        0,
        index,
        Source::Input,
        CellField::Capacity,
    ) {
        Ok(8) => {
            let capacity = u64::from_le_bytes(capacity_buf);

            let mut current_script_hash = [0u8; HASH_SIZE];
            let ret = ckb_std::syscalls::load_cell_by_field(
                &mut current_script_hash,
                0,
                index,
                Source::Input,
                CellField::TypeHash,
            );
            dao_input = match ret {
                Ok(HASH_SIZE) => &current_script_hash == script_hash,
                Ok(_) => false,
                Err(_) => false,
            };

            if !dao_input {
                *input_capacities = input_capacities
                    .checked_add(capacity)
                    .ok_or(ERROR_OVERFLOW)?;
            } else {
                // Determine whether this is a deposited or withdrawing cell.
                let mut block_number_buf = [0u8; 8];
                match ckb_std::syscalls::load_cell_data(
                    &mut block_number_buf,
                    0,
                    index,
                    Source::Input,
                ) {
                    Ok(8) => {}
                    Ok(_) => return Err(ERROR_SYSCALL),
                    Err(_) => return Err(ERROR_SYSCALL),
                }
                let block_number = u64::from_le_bytes(block_number_buf);

                if block_number > 0 {
                    let dao_capacity = calculate_dao_input_capacity(index, block_number, capacity)?;
                    *input_capacities = input_capacities
                        .checked_add(dao_capacity)
                        .ok_or(ERROR_OVERFLOW)?;
                } else {
                    validate_withdrawing_cell(index, capacity, script_hash)?;
                    *output_withdrawing = true;
                    *input_capacities = input_capacities
                        .checked_add(capacity)
                        .ok_or(ERROR_OVERFLOW)?;
                }
            }
        }
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(SysError::IndexOutOfBound) => return Err(ERROR_MARKER_EXHAUSTED),
        Err(_) => return Err(ERROR_SYSCALL),
    }

    Ok(())
}

fn validate_output(
    index: usize,
    output_capacities: &mut u64,
    output_withdrawing: bool,
    script_hash: &[u8; HASH_SIZE],
) -> Result<(), i8> {
    let mut capacity_buf = [0u8; 8];
    match ckb_std::syscalls::load_cell_by_field(
        &mut capacity_buf,
        0,
        index,
        Source::Output,
        CellField::Capacity,
    ) {
        Ok(8) => {
            let capacity = u64::from_le_bytes(capacity_buf);
            *output_capacities = output_capacities
                .checked_add(capacity)
                .ok_or(ERROR_OVERFLOW)?;

            let mut current_script_hash = [0u8; HASH_SIZE];
            match ckb_std::syscalls::load_cell_by_field(
                &mut current_script_hash,
                0,
                index,
                Source::Output,
                CellField::TypeHash,
            ) {
                Ok(HASH_SIZE) => {
                    if &current_script_hash == script_hash && !output_withdrawing {
                        // Newly deposited cell must contain 8 bytes of zero data.
                        let mut block_number_buf = [0u8; 8];
                        match ckb_std::syscalls::load_cell_data(
                            &mut block_number_buf,
                            0,
                            index,
                            Source::Output,
                        ) {
                            Ok(8) => {}
                            Ok(_) => return Err(ERROR_SYSCALL),
                            Err(_) => return Err(ERROR_SYSCALL),
                        }
                        let block_number = u64::from_le_bytes(block_number_buf);
                        if block_number != 0 {
                            return Err(ERROR_NEWLY_CREATED_CELL);
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        Ok(_) => return Err(ERROR_SYSCALL),
        Err(SysError::IndexOutOfBound) => return Err(ERROR_MARKER_EXHAUSTED),
        Err(_) => return Err(ERROR_SYSCALL),
    }

    Ok(())
}

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
    if !script_reader.args().raw_data().is_empty() {
        return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
    }

    // Load current script hash.
    let mut script_hash = [0u8; HASH_SIZE];
    match ckb_std::syscalls::load_script_hash(&mut script_hash, 0) {
        Ok(HASH_SIZE) => {}
        Ok(_) => return ERROR_SYSCALL,
        Err(_) => return ERROR_SYSCALL,
    }

    let mut index: usize = 0;
    let mut input_capacities: u64 = 0;
    let mut output_capacities: u64 = 0;
    let mut input_exhausted = false;
    let mut output_exhausted = false;

    while !(input_exhausted && output_exhausted) {
        let mut output_withdrawing = false;

        if !input_exhausted {
            match validate_input(
                index,
                &mut input_capacities,
                &mut output_withdrawing,
                &script_hash,
            ) {
                Ok(()) => {}
                Err(ERROR_MARKER_EXHAUSTED) => input_exhausted = true,
                Err(err) => return err,
            }
        }

        if !output_exhausted {
            match validate_output(
                index,
                &mut output_capacities,
                output_withdrawing,
                &script_hash,
            ) {
                Ok(()) => {}
                Err(ERROR_MARKER_EXHAUSTED) => output_exhausted = true,
                Err(err) => return err,
            }
        }

        index += 1;
    }

    if output_capacities > input_capacities {
        return ERROR_INCORRECT_CAPACITY;
    }

    0
}
