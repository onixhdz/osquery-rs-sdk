# osquery-rs-sdk

[![Crates.io][crate-image]][crate-link]
[![Documentation][docs-image]][docs-link]
[![CI][ci-image]][ci-link]
[![MIT Licensed][license-image]][license-link]

A feature-complete Rust SDK for building [osquery](https://osquery.io) extensions: custom tables, writable tables, loggers, config providers, and distributed query handlers that connect to `osqueryd` or `osqueryi` through osquery's extension socket.

osquery exposes operating system state as SQL tables. Extensions let you add more tables and plugin behavior without patching osquery itself.

## What is osquery-rs-sdk?

This crate provides a Rust SDK for osquery's extension API. An extension is a normal executable: create an `ExtensionManagerServer`, register the plugins it should expose, and run it against the extension socket used by `osqueryd` or `osqueryi`.

There is no C/C++ build step for users of the crate. On Linux and macOS the SDK talks to osquery over Unix sockets; on Windows it uses named pipes. For lower-level details on the extension lifecycle, see the osquery [SDK documentation](https://osquery.readthedocs.io/en/latest/development/osquery-sdk/).

## Features

- **Table plugins:** Define virtual tables queryable with SQL, including writable tables with INSERT/UPDATE/DELETE handlers
- **Logger plugins:** Handle osquery event and result logs
- **Config plugins:** Provide dynamic config and generate query packs on demand
- **Distributed plugins:** Serve distributed queries and collect results
- **Client API:** Query a running osquery instance from Rust
- **Custom plugins:** Implement `OsqueryPlugin` directly for behavior beyond the built-in plugin types
- **Mock support:** Test extension code without a live `osqueryd`
- **Builder API:** Set version strings, timeouts, and ping intervals
- **Signal handling:** Handle SIGINT/SIGTERM on Unix and Ctrl+C on Windows
- **Cross-platform transport:** Unix sockets on Linux/macOS and named pipes on Windows

## Quick start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
osquery-rs-sdk = "0.2.0"
```

### Query a running osquery instance

```rust
fn main() -> osquery_rs_sdk::Result<()> {
    let mut client = osquery_rs_sdk::ExtensionManagerClient::connect()?;
    let rows = client.query("SELECT * FROM users LIMIT 5")?;
    println!("{rows:?}");
    Ok(())
}
```

### Handle errors

Transport failures and osquery-level failures are distinct error variants,
so retry logic never needs to parse message strings:

```rust
use osquery_rs_sdk::Error;

match client.query("SELECT * FROM maybe_missing") {
    Ok(rows) => println!("{rows:?}"),
    // osquery replied: bad SQL, unknown table, ... Do not retry.
    Err(Error::Status { code, message }) => eprintln!("query failed ({code}): {message}"),
    // Connection problem: may succeed after reconnecting.
    Err(other) => return Err(other),
}
```

### Create a custom table

```rust
use osquery_rs_sdk::{
    ColumnDefinition, ExtensionManagerServer, QueryContext, Result, Table, TablePlugin,
};
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_extension", "/var/osquery/osquery.em")?;
    server.register_plugin(TablePlugin::new("my_table", columns(), generate))?;
    server.run()
}

fn columns() -> Vec<ColumnDefinition> {
    vec![
        ColumnDefinition::text("name"),
        ColumnDefinition::integer("age"),
    ]
}

fn generate(_ctx: QueryContext) -> Result<Table> {
    Ok(vec![BTreeMap::from([
        ("name".into(), "Alice".into()),
        ("age".into(), "30".into()),
    ])])
}
```

### Create a writable table

Implement `WritableTable` when osquery should be able to mutate table state:

```rust
use osquery_rs_sdk::{
    ColumnDefinition, DeleteRequest, ExtensionManagerServer, InsertRequest,
    MutationResult, QueryContext, Result, Table, UpdateRequest,
    WritableTable, WritableTablePlugin,
};

struct MyTable;

impl WritableTable for MyTable {
    fn name(&self) -> &str { "my_table" }
    fn columns(&self) -> Vec<ColumnDefinition> { vec![] }
    fn generate(&mut self, _ctx: QueryContext) -> Result<Table> { Ok(vec![]) }
    fn insert(&mut self, req: InsertRequest) -> Result<MutationResult> {
        Ok(MutationResult::Success { row_id: req.row_id })
    }
    fn update(&mut self, _req: UpdateRequest) -> Result<MutationResult> {
        Ok(MutationResult::Success { row_id: None })
    }
    fn delete(&mut self, _req: DeleteRequest) -> Result<MutationResult> {
        Ok(MutationResult::Success { row_id: None })
    }
}

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_ext", "/var/osquery/osquery.em")?;
    server.register_plugin(WritableTablePlugin::new(MyTable))?;
    server.run()
}
```

Writable table methods receive `&mut self`, so table state can usually live on the plugin struct instead of behind a lock.

### Create a logger plugin

```rust
use osquery_rs_sdk::{ExtensionManagerServer, LogType, LoggerPlugin, Result};

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_logger", "/var/osquery/osquery.em")?;
    server.register_plugin(
        LoggerPlugin::new("my_logger", log_string)
            .with_shutdown(|| { /* flush buffers, release resources */ }),
    )?;
    server.run()
}

fn log_string(typ: LogType, message: &str) -> Result<()> {
    println!("{typ}: {message}");
    Ok(())
}
```

### Create a config plugin

```rust
use osquery_rs_sdk::{ConfigPlugin, ExtensionManagerServer, Result};
use std::collections::BTreeMap;

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::new("my_config", "/var/osquery/osquery.em")?;
    server.register_plugin(
        ConfigPlugin::new("my_config", generate_config)
            .with_gen_pack(|_name, _value| {
                // Resolve query packs on demand (e.g. fetch from a remote source)
                Ok(format!(r#"{{"queries":{{"q1":{{"query":"SELECT 1;","interval":60}}}}}}"#))
            }),
    )?;
    server.run()
}

fn generate_config() -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([(
        "config1".into(),
        r#"{"schedule": {"info": {"query": "SELECT * FROM osquery_info;", "interval": 60}}}"#.into(),
    )]))
}
```

### Graceful shutdown

`run_with_signal_handling()` handles SIGINT/SIGTERM on Unix and Ctrl+C on Windows:

```rust
let mut server = ExtensionManagerServer::new("my_ext", "/var/osquery/osquery.em")?;
// ... register plugins ...
server.run_with_signal_handling()?;
```

Use `ShutdownHandle` when another thread needs to stop the server:

```rust
use osquery_rs_sdk::ExtensionManagerServer;

let mut server = ExtensionManagerServer::new("my_ext", "/var/osquery/osquery.em")?;
let handle = server.shutdown_handle();

std::thread::spawn(move || {
    handle.shutdown();
});

server.run()?;
```

### Server configuration

```rust
use osquery_rs_sdk::{ExtensionManagerServer, Result};
use std::time::Duration;

fn main() -> Result<()> {
    let mut server = ExtensionManagerServer::builder("my_ext", "/var/osquery/osquery.em")
        .version("1.0.0")
        .ping_interval(Duration::from_secs(10))
        .build()?;

    // ... register plugins ...
    server.run()
}
```

## Feature flags

| Flag      | Default | Description                                                           |
| --------- | ------- | --------------------------------------------------------------------- |
| `client`  | no      | Client API for querying osquery                                       |
| `server`  | yes     | Extension server; also enables `client`                               |
| `plugins` | yes     | Table, logger, config, and distributed plugins; also enables `server` |
| `mock`    | no      | Mock implementations for tests                                        |
| `tracing` | no      | Structured logging through the `tracing` crate                        |

## Loading an extension with osqueryd

osquery only loads extension binaries from paths it trusts. A typical root-run `osqueryd` setup looks like this:

1. Build the extension and give the binary a `.ext` suffix:

```bash
cargo build --release --example table
cp target/release/examples/table target/release/examples/table.ext
```

2. Put the extension somewhere only root or the osqueryd service owner can write to:

```bash
sudo mkdir -p /usr/local/osquery_extensions
sudo chown root:root /usr/local/osquery_extensions
sudo chmod 755 /usr/local/osquery_extensions
sudo cp target/release/examples/table.ext /usr/local/osquery_extensions/
```

3. Create an `extensions.load` file in a trusted location:

```bash
sudo mkdir -p /etc/osquery
echo "/usr/local/osquery_extensions/table.ext" | sudo tee /etc/osquery/extensions.load >/dev/null
```

4. Start osqueryd with extension autoloading:

```bash
sudo osqueryd --extensions_autoload=/etc/osquery/extensions.load --verbose
```

## Testing

```bash
# Unit tests, no osqueryd required
cargo test --all-features

# Full suite, including ignored tests that require a live osqueryd
cargo test --all-features -- --include-ignored
```

## Dev container

The `.devcontainer/` setup installs Rust, the Thrift compiler, and `osqueryd`. It also starts `osqueryd` on the standard socket path (`/var/osquery/osquery.em`), so the ignored integration tests can run inside the container:

```bash
cargo test --all-features -- --include-ignored
```

Restart the daemon manually if needed:

```bash
.devcontainer/scripts/stop-osqueryd.sh
.devcontainer/scripts/start-osqueryd.sh
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development, testing, and pull request guidelines.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md) for details.

## License

[MIT](LICENSE)

## Acknowledgments

This project was influenced by [osquery-go](https://github.com/osquery/osquery-go).

[crate-image]: https://img.shields.io/crates/v/osquery-rs-sdk.svg
[crate-link]: https://crates.io/crates/osquery-rs-sdk
[docs-image]: https://docs.rs/osquery-rs-sdk/badge.svg
[docs-link]: https://docs.rs/osquery-rs-sdk
[ci-image]: https://github.com/onixhdz/osquery-rs-sdk/actions/workflows/ci.yml/badge.svg
[ci-link]: https://github.com/onixhdz/osquery-rs-sdk/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-link]: https://github.com/onixhdz/osquery-rs-sdk/blob/main/LICENSE
