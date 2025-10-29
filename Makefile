.PHONY: all build-nostd build-lib-std build-lib-all build-lib-nostd test test-lib test-std test-nostd clean bench

SRC = $(wildcard src/**/*.rs src/*.rs)

all: build-lib-all

build-lib-all: build-lib-std build-lib-nostd

build-lib-std: Cargo.toml $(SRC)
	cargo build --lib --features std

build-lib-nostd: Cargo.toml $(SRC)
	cargo build --lib --no-default-features --features no_std

test: test-lib

test-lib: test-std

test-std: Cargo.toml $(SRC)
	cargo test --lib --features std

test-all: test-std test-nostd

clean:
	cargo clean

bench:
	cargo bench -- --nocapture
