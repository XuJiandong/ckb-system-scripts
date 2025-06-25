#!/bin/bash
# set -ex

build_with_clang() {
    local clang_version=$1

    echo "Building with clang-$clang_version..."

    make -f Makefile.clang clean

    CLANG_VERSION=$clang_version
    make -f Makefile.clang all \
        CC=clang-$CLANG_VERSION \
        LD=ld.lld-$CLANG_VERSION \
        OBJCOPY=llvm-objcopy-$CLANG_VERSION \
        AR=llvm-ar-$CLANG_VERSION

    cp specs/cells/secp256k1_blake160_sighash_all \
       specs/cells/secp256k1_blake160_sighash_all_llvm_$CLANG_VERSION

    clang-$CLANG_VERSION --version

    echo "Build completed for clang-$clang_version"
    echo "----------------------------------------"
}

echo "Building all versions..."

build_with_clang 18

build_with_clang 19

build_with_clang 20

echo "Running benchmark test..."
cargo test --features="test_llvm_version" --lib -- tests::secp256k1_blake160_sighash_all::test_sighash_benchmark --exact --show-output --nocapture