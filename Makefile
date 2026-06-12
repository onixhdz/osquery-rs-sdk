.PHONY: setup fmt lint doc build test test-ignored audit deny check clean

# Install developer tools (cargo-audit, cargo-deny, cargo-nextest)
setup:
	cargo install cargo-audit cargo-deny cargo-nextest --locked

# Format check
fmt:
	cargo fmt --check

# Lint with strict warnings
lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Documentation check (broken links, bare URLs)
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Build all features
build:
	cargo build --workspace --all-features

# Run unit tests
test:
	cargo test --workspace --all-features

# Run integration tests (requires a running osqueryd)
test-ignored:
	cargo test --workspace --all-features -- --ignored

# Security audit (RustSec advisories)
audit:
	cargo audit

# Dependency policy check (licenses, sources, duplicates)
deny:
	cargo deny check

# Run all CI checks locally
check: fmt lint doc build test audit deny
