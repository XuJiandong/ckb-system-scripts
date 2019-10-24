/*
 * This script implements Bitcoin lock validation in ckb.
 *
 * How to verify Bitcoin lock?
 *
 * We know that the format of the Bitcoin address is
 * base58(version + ripemd160(sha256(pubkey)) + sha256(sha256(version +
 * ripemd160(sha256(pubkey))))[0..4])
 *
 * So by verifying the hash of ripemd160(sha256(pubkey)) and verifying the
 * ownership of the pubkey, you can achieve the purpose of verifying the
 * ownership of the private key.
 *
 * How to use this script?
 *
 * We need verify ripemd160(sha256(pubkey)), so transaction lock script like
 * this:
 *
 * ```
 * dependence_code_hash = "this script binary hash"
 * args = [ "ripemd160(sha256(pubkey))" ]
 * ```
 *
 * We need verify the ownership of the pubkey, so transaction witness is:
 *
 * witness = [signature, pubkey]
 *
 * Signature generated by your private key sign transaction hash
 */
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "ripemd160.h"
#include "secp256k1_helper.h"
#include "sha256.h"

#define BLAKE2B_BLOCK_SIZE 32
#define RIPEMD160_SIZE 20
#define SHA256_SIZE 32
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define RECOVERABLE_SIGNATURE_SIZE 65
#define NONE_RECOVERABLE_SIGNATURE_SIZE 64
#define COMPRESSED_PUBKEY_SIZE 33
#define NONE_COMPRESSED_PUBKEY_SIZE 65
/* RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE */
#define MAX_LOCK_SIZE 130

/*
 * Arguments are listed in the following order:
 * 0. ripemd160(sha256(pubkey)) hash, used to
 * shield the real pubkey in lock script.
 *
 * Witness:
 * 0. signature, signature used to present ownership
 * 1. pubkey, real pubkey used to identify token owner
 */
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  unsigned char temp[TEMP_SIZE];
  unsigned char witness[MAX_WITNESS_SIZE];
  unsigned char script[SCRIPT_SIZE];
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  mol_seg_t script_seg;
  mol_seg_t args_seg;
  mol_seg_t bytes_seg;

  /* Load args */
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  args_seg = MolReader_Script_get_args(&script_seg);
  bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (bytes_seg.size != RIPEMD160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  /* Now we load actual witness data using the same input index above. */
  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  uint64_t lock_len = lock_bytes_seg.size;
  if (lock_len != RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE &&
      lock_len != RECOVERABLE_SIGNATURE_SIZE + COMPRESSED_PUBKEY_SIZE &&
      lock_len !=
          NONE_RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE &&
      lock_len != NONE_RECOVERABLE_SIGNATURE_SIZE + COMPRESSED_PUBKEY_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  secp256k1_context context;
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_compact(&context, &signature,
                                              lock_bytes_seg.ptr) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* parse pubkey */
  secp256k1_pubkey pubkey;
  uint64_t signature_len;
  if (lock_len == RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE ||
      lock_len ==
          NONE_RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE) {
    signature_len = lock_len - NONE_COMPRESSED_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_parse(&context, &pubkey,
                                  lock_bytes_seg.ptr + signature_len,
                                  NONE_COMPRESSED_PUBKEY_SIZE) == 0) {
      return ERROR_SECP_PARSE_PUBKEY;
    }
  } else {
    signature_len = lock_len - COMPRESSED_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_parse(&context, &pubkey,
                                  lock_bytes_seg.ptr + signature_len,
                                  COMPRESSED_PUBKEY_SIZE) == 0) {
      return ERROR_SECP_PARSE_PUBKEY;
    }
  }

  /* check pubkey hash */
  sha256_state sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, lock_bytes_seg.ptr + signature_len,
                lock_len - signature_len);
  sha256_finalize(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, temp);
  if (memcmp(bytes_seg.ptr, temp, RIPEMD160_SIZE) != 0) {
    return ERROR_PUBKEY_RIPEMD160_HASH;
  }

  /* Calculate signature message */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  /* Clear lock field signature to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, signature_len);
  sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
  sha256_update(&sha256_ctx, witness, len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
    i += 1;
  }

  /* Digest witnesses that not covered by inputs */
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
    i += 1;
  }

  sha256_finalize(&sha256_ctx, temp);

  /* verify signature */
  if (secp256k1_ecdsa_verify(&context, &signature, temp, &pubkey) != 1) {
    return ERROR_SECP_VERIFICATION;
  }

  return 0;
}
