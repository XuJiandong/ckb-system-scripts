cmake_minimum_required(VERSION 3.15)
project(xjd_ckb_system_scripts C)

set(CMAKE_C_STANDARD 11)

add_definitions(-DUSE_SIM)
include_directories(build)
include_directories(c)
include_directories(deps/molecule)
include_directories(deps/secp256k1)
include_directories(deps/secp256k1/src)
include_directories(simulator)

link_directories(deps/secp256k1/.libs)
link_libraries(libsecp256k1.a)

add_executable(secp256k1_blake160_multisig_all
        build/secp256k1_data_info.h
        c/blake2b.h
        c/ckb_consts.h
        c/ckb_syscalls.h
        c/common.h
        c/protocol.h
        c/secp256k1_blake160_sighash_all.c
        c/secp256k1_helper.h
        c/utils.h
        deps/molecule/molecule_builder.h
        deps/molecule/molecule_reader.h
        deps/secp256k1/include/secp256k1.h
        deps/secp256k1/include/secp256k1_ecdh.h
        deps/secp256k1/include/secp256k1_preallocated.h
        deps/secp256k1/include/secp256k1_recovery.h
        simulator/ckb_syscall_sim.h)
