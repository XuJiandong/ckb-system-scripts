cmake_minimum_required(VERSION 3.15)
project(xjd_ckb_system_scripts C)

set(CMAKE_C_STANDARD 11)

include_directories(deps/molecule)
include_directories(deps/secp256k1/src)
include_directories(deps/secp256k1)
include_directories(build)
add_executable(xjd_ckb_system_scripts c/secp256k1_blake160_sighash_all.c)
