.PHONY: all
all: build

.PHONY: build
build:
	cargo build --release

target: build

.PHONY: test
test:
	cargo fmt --check
	cargo clippy --tests --locked
	cargo test --locked --release -- --nocapture

clean:
	rm -rf target
