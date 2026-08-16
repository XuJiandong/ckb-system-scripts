TARGET := riscv64imac-unknown-none-elf
CONTRACT_PKG := ckb-system-scripts-contract
CONTRACT_DIR := contracts/system-scripts
CELLS_DIR := specs/cells

BINARIES := \
	$(CELLS_DIR)/secp256k1_blake160_sighash_all \
	$(CELLS_DIR)/secp256k1_blake160_multisig_all \
	$(CELLS_DIR)/dao

.PHONY: all build test clean prepare

all: build

prepare:
	rustup target add $(TARGET)

build: $(BINARIES)

$(BINARIES): $(CONTRACT_DIR)/Cargo.toml $(CONTRACT_DIR)/src/lib.rs $(CONTRACT_DIR)/src/bin/*.rs
	mkdir -p $(CELLS_DIR)
	RUSTFLAGS="-C link-arg=-z -C link-arg=separate-code -C target-feature=+relax" cargo build -p $(CONTRACT_PKG) --target $(TARGET) --release
	cp target/$(TARGET)/release/$(notdir $@) $@

test: build
	cargo test $(CARGO_ARGS)

clean:
	rm -rf $(CELLS_DIR)/secp256k1_blake160_sighash_all
	rm -rf $(CELLS_DIR)/secp256k1_blake160_multisig_all
	rm -rf $(CELLS_DIR)/dao
	cargo clean
