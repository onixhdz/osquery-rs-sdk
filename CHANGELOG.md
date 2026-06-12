# Changelog

## 0.2.0 - 2026-06-12

Breaking release: the public API no longer exposes `thrift` crate types or
unnameable generated wire types. All public signatures use SDK-owned types,
and osquery status codes are folded into the crate's `Error`.

### Migration

- All client methods now return `osquery_rs_sdk::Result<T>` instead of
  `thrift::Result<T>`. Match `Error::Transport` for connection failures and
  the new `Error::Status { code, message }` for osquery-level failures.
- `query()` returns the result rows directly (`PluginResponse`); a non-zero
  status is now an `Err(Error::Status { .. })`. `query_rows()` was removed
  (redundant with `query()`); `query_row()` remains.
- `ping()` returns `Result<()>`; non-zero status codes become
  `Err(Error::Status { .. })`.
- `extensions()` returns `Vec<ExtensionInfo>` (uuid included) and
  `options()` returns `BTreeMap<String, OptionInfo>` instead of generated
  wire maps.
- `ExtensionManagerClient::from_protocols` was removed. Construct clients
  with `connect`, `connect_with_path`, or `connect_with_timeout`.
- `ExtensionManagerClient::shutdown` (the RPC asking osquery core to shut
  down) was removed from the public client.
- The `ExtensionManager` trait is now sealed and fully SDK-typed. Use
  `MockExtensionManager` (`mock` feature) for test doubles; its `*_fn`
  fields use the new signatures.
- `OsqueryPlugin` is now implementable outside the crate:
  `call(&mut self, PluginRequest) -> Result<PluginResponse>`. Return
  `Err(Error::Status { code, message })` to control the status code
  reported to osquery; any other error maps to status 1 with the error's
  message.
- New crate-root aliases: `PluginRequest`, `PluginResponse`,
  `ExtensionUuid`, `ExtensionRegistry`.

### Fixed

- Windows: `NamedPipeClient::close()` now cancels in-flight blocking reads
  and writes (`CancelIoEx`), matching Unix `shutdown(Both)` behavior.
  Previously a thread blocked in `read` was not woken.

### Changed

- Upgraded `thrift` to 0.23.0 (CVE-2026-43868 / GHSA-2f9f-gq7v-9h6m):
  protocol constructors now bound allocations from untrusted wire data.
- `LoggerPlugin::with_shutdown` no longer has a documented panic path.
- Timing-sensitive server tests poll for readiness instead of fixed sleeps.

## 0.1.1

Initial published release.
