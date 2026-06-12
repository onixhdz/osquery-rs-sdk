# AGENTS.md

## Context

This crate ships into security-sensitive environments and promises a thin, zero-unnecessary-overhead layer over osquery's extension API. Reliability and minimal footprint outrank convenience: code must not crash the host process, bloat the dependency tree, or add runtime cost the thrift boundary doesn't require.

## Hard Rules

- Never hand-edit `src/osquery.rs`; regenerate it from `osquery.thrift` with the Thrift compiler.
- Do not leak `thrift` crate types into the public API; wrap them in SDK-owned types.
- Every public item is a stability contract on a published crate. Minimize surface; treat additions to public API as compatibility-sensitive.
- New dependencies must be optional behind a feature unless `client` itself needs them, and must pass `cargo deny` and `cargo audit`.
- Do not use language features newer than the pinned `rust-version` without bumping it deliberately.

## Error Handling

Extensions run inside the osquery process tree; a panic takes down the whole extension.

- No `unwrap`, `expect`, `panic!`, or slice indexing in library code. Return `Result<T, Error>` for all operational failures.
- Use the crate's `thiserror`-based error enum; add precise variants instead of stringly errors so callers can match without string parsing.
- Preserve context in errors (plugin name, socket path, thrift call) so failures are diagnosable from osquery logs.
- Treat wire data from osquery as untrusted: handle malformed payloads, disconnects, and invalid plugin requests as errors, never as panics.

## Conventions

- Platform-specific code lives in explicit `#[cfg(...)]` modules; everything else stays platform-agnostic. Windows named pipes and Unix sockets must keep behavior parity.
- Test-only utilities go behind the `mock` feature, not `#[cfg(test)]` seams on production types. Keep mocks in sync with real transport behavior.
- Tests requiring a live `osqueryd` are `#[ignore]`d.
- No allocation, cloning, or formatting on the dispatch hot path unless the thrift boundary requires it. `tracing` must be zero-cost when the feature is off.
- When feature gating changes, update `required-features` on examples and benches and verify each feature still compiles standalone.
- No verbose comments: no narration of what the code does, no decorative banners, no commented-out code. Keep comments that explain why, document contracts or safety requirements, and rustdoc on public items (it ships to docs.rs).

## Verification

- Strictly validate every code change against the rules in this document before calling it done or commit-ready.
- Use the devcontainer when the environment requires it.
- Always pass `--all-features` to build/test/clippy; defaults exclude `mock` and `tracing`.
- Run `make check` (fmt, clippy `-D warnings`, doc, build, test, audit, deny) before calling work complete. `make lint` and `make test` suffice for iteration.
- `make test-ignored` runs live-osqueryd integration tests when one is available.
