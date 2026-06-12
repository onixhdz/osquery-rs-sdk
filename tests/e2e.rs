//! End-to-end integration tests exercising the SDK as an actual user would.
//!
//! These tests require a running osqueryd with an extension socket at
//! `/var/osquery/osquery.em` (override with the `OSQUERY_SOCKET` environment
//! variable). Run them with:
//!
//! ```sh
//! cargo test --all-features --test e2e -- --ignored
//! ```

// Panic/print allowances for test code live in clippy.toml; these pedantic
// lints have no test toggle.
#![allow(clippy::semicolon_if_nothing_returned, clippy::needless_pass_by_value)]

use osquery_rs_sdk::{
    ColumnDefinition, ConfigPlugin, DeleteRequest, DistributedPlugin, ExtensionManagerClient,
    ExtensionManagerServer, InsertRequest, LogType, LoggerPlugin, MutationResult, QueriesRequest,
    QueryContext, QueryResponse, Result, Table, TablePlugin, UpdateRequest, WritableTable,
    WritableTablePlugin,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(unix)]
const DEFAULT_OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const DEFAULT_OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

/// Path to the osqueryd extension socket, overridable via `OSQUERY_SOCKET`
/// so the suite can run against an unprivileged osqueryd instance.
fn osquery_socket() -> String {
    std::env::var("OSQUERY_SOCKET").unwrap_or_else(|_| DEFAULT_OSQUERY_SOCKET.to_string())
}

// ---------------------------------------------------------------------------
// 1. Client: connect, query, query_rows, query_row
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn client_connect_and_query() {
    // Exercise the default-socket `connect()` unless the suite has been
    // pointed at an alternate socket via `OSQUERY_SOCKET`.
    let mut client = match std::env::var("OSQUERY_SOCKET") {
        Ok(path) => ExtensionManagerClient::connect_with_path(path),
        Err(_) => ExtensionManagerClient::connect(),
    }
    .expect("should connect to osqueryd");

    // ping
    let status = client.ping().expect("ping should succeed");
    assert_eq!(status.code.unwrap_or(-1), 0, "ping status should be OK");

    // raw query
    let resp = client
        .query("SELECT 1 AS value")
        .expect("query should succeed");
    let status = resp.status.expect("response should have status");
    assert_eq!(status.code.unwrap_or(-1), 0, "query status should be OK");
    let rows = resp.response.expect("response should have rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("value").map(String::as_str), Some("1"));
}

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn client_query_rows_and_query_row() {
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");

    // query_rows
    let rows = client
        .query_rows("SELECT 1 AS a, 2 AS b")
        .expect("query_rows should succeed");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("a").map(String::as_str), Some("1"));
    assert_eq!(rows[0].get("b").map(String::as_str), Some("2"));

    // query_row -- exactly one row
    let row = client
        .query_row("SELECT 42 AS answer")
        .expect("query_row should succeed");
    assert_eq!(row.get("answer").map(String::as_str), Some("42"));

    // query_row -- zero rows should error
    let err = client.query_row("SELECT 1 WHERE 1=0");
    assert!(err.is_err(), "query_row with 0 rows should error");
}

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn client_connect_with_timeout() {
    let client =
        ExtensionManagerClient::connect_with_timeout(osquery_socket(), Duration::from_secs(5));
    assert!(client.is_ok(), "connect_with_timeout should succeed");
}

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn client_close_then_ping_fails() {
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");
    client.ping().expect("first ping should succeed");
    client.close();
    assert!(client.ping().is_err(), "ping after close should fail");
}

// ---------------------------------------------------------------------------
// 2. Server + TablePlugin: register, run, query via osqueryd, verify data
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn table_plugin_e2e() {
    let columns = vec![
        ColumnDefinition::text("greeting"),
        ColumnDefinition::integer("count"),
    ];

    let generate_fn = |_ctx: osquery_rs_sdk::QueryContext| -> Result<Table> {
        Ok(vec![
            BTreeMap::from([
                ("greeting".into(), "hello".into()),
                ("count".into(), "1".into()),
            ]),
            BTreeMap::from([
                ("greeting".into(), "world".into()),
                ("count".into(), "2".into()),
            ]),
        ])
    };

    // run() blocks, so spawn in background
    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_table_ext", osquery_socket())
            .expect("server should create");
        server
            .register_plugin(TablePlugin::new("e2e_table", columns, generate_fn))
            .expect("register_plugin should succeed");
        // run() blocks until osquery pings fail or shutdown is called
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("client should connect");

    let rows = client
        .query_rows("SELECT * FROM e2e_table")
        .expect("query on e2e_table should succeed");

    assert_eq!(rows.len(), 2, "should return 2 rows");
    assert_eq!(rows[0].get("greeting").map(String::as_str), Some("hello"));
    assert_eq!(rows[0].get("count").map(String::as_str), Some("1"));
    assert_eq!(rows[1].get("greeting").map(String::as_str), Some("world"));
    assert_eq!(rows[1].get("count").map(String::as_str), Some("2"));

    // Query with a WHERE clause
    let rows = client
        .query_rows("SELECT greeting FROM e2e_table WHERE count = '2'")
        .expect("filtered query should succeed");
    assert_eq!(rows.len(), 1, "WHERE clause should filter to 1 row");
    assert_eq!(rows[0].get("greeting").map(String::as_str), Some("world"));

    // Drop triggers shutdown
    drop(handle);
}

// ---------------------------------------------------------------------------
// 2b. Writable TablePlugin: INSERT, SELECT, UPDATE, DELETE via osqueryd
// ---------------------------------------------------------------------------

struct E2eWritableTable {
    data: BTreeMap<i64, (String, String)>,
}

impl E2eWritableTable {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }
}

impl WritableTable for E2eWritableTable {
    fn name(&self) -> &'static str {
        "e2e_writable"
    }

    fn columns(&self) -> Vec<ColumnDefinition> {
        vec![
            ColumnDefinition::text("key").index(),
            ColumnDefinition::text("value"),
        ]
    }

    fn generate(&mut self, _ctx: QueryContext) -> Result<Table> {
        Ok(self
            .data
            .values()
            .map(|(k, v)| {
                BTreeMap::from([
                    ("key".to_string(), k.clone()),
                    ("value".to_string(), v.clone()),
                ])
            })
            .collect())
    }

    fn insert(&mut self, req: InsertRequest) -> Result<MutationResult> {
        let key = req
            .values
            .first()
            .and_then(Clone::clone)
            .unwrap_or_default();
        let value = req.values.get(1).and_then(Clone::clone).unwrap_or_default();
        let row_id = req.row_id.unwrap_or(0);
        self.data.insert(row_id, (key, value));
        Ok(MutationResult::Success {
            row_id: Some(row_id),
        })
    }

    fn update(&mut self, req: UpdateRequest) -> Result<MutationResult> {
        let key = req
            .values
            .first()
            .and_then(Clone::clone)
            .unwrap_or_default();
        let value = req.values.get(1).and_then(Clone::clone).unwrap_or_default();
        let id = req.new_row_id.unwrap_or(req.row_id);
        self.data.remove(&req.row_id);
        self.data.insert(id, (key, value));
        Ok(MutationResult::Success { row_id: None })
    }

    fn delete(&mut self, req: DeleteRequest) -> Result<MutationResult> {
        self.data.remove(&req.row_id);
        Ok(MutationResult::Success { row_id: None })
    }
}

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn writable_table_plugin_e2e() {
    let plugin = WritableTablePlugin::new(E2eWritableTable::new());

    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_writable_ext", osquery_socket())
            .expect("server should create");
        server
            .register_plugin(plugin)
            .expect("register_plugin should succeed");
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("client should connect");

    // 1. Table should start empty
    let rows = client
        .query_rows("SELECT * FROM e2e_writable")
        .expect("SELECT on empty writable table should succeed");
    assert_eq!(rows.len(), 0, "writable table should start empty");

    // 2. INSERT a row
    let resp = client
        .query("INSERT INTO e2e_writable (key, value) VALUES ('greeting', 'hello')")
        .expect("INSERT should succeed");
    let status = resp.status.expect("INSERT response should have status");
    assert_eq!(
        status.code.unwrap_or(-1),
        0,
        "INSERT status should be OK: {:?}",
        status.message
    );

    // 3. SELECT should return the inserted row
    let rows = client
        .query_rows("SELECT key, value FROM e2e_writable")
        .expect("SELECT after INSERT should succeed");
    assert_eq!(rows.len(), 1, "should have 1 row after INSERT");
    assert_eq!(
        rows[0].get("key").map(String::as_str),
        Some("greeting"),
        "key should be 'greeting'"
    );
    assert_eq!(
        rows[0].get("value").map(String::as_str),
        Some("hello"),
        "value should be 'hello'"
    );

    // 4. UPDATE the row
    let resp = client
        .query("UPDATE e2e_writable SET value = 'world' WHERE key = 'greeting'")
        .expect("UPDATE should succeed");
    let status = resp.status.expect("UPDATE response should have status");
    assert_eq!(
        status.code.unwrap_or(-1),
        0,
        "UPDATE status should be OK: {:?}",
        status.message
    );

    // 5. Verify the update
    let rows = client
        .query_rows("SELECT key, value FROM e2e_writable")
        .expect("SELECT after UPDATE should succeed");
    assert_eq!(rows.len(), 1, "should still have 1 row after UPDATE");
    assert_eq!(
        rows[0].get("value").map(String::as_str),
        Some("world"),
        "value should be updated to 'world'"
    );

    // 6. DELETE the row
    let resp = client
        .query("DELETE FROM e2e_writable WHERE key = 'greeting'")
        .expect("DELETE should succeed");
    let status = resp.status.expect("DELETE response should have status");
    assert_eq!(
        status.code.unwrap_or(-1),
        0,
        "DELETE status should be OK: {:?}",
        status.message
    );

    // 7. Table should be empty again
    let rows = client
        .query_rows("SELECT * FROM e2e_writable")
        .expect("SELECT after DELETE should succeed");
    assert_eq!(rows.len(), 0, "table should be empty after DELETE");

    drop(handle);
}

// ---------------------------------------------------------------------------
// 3. Server + ConfigPlugin: register and call via osqueryd
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn config_plugin_e2e() {
    let call_count = Arc::new(Mutex::new(0u32));

    let generate = move || -> Result<BTreeMap<String, String>> {
        *call_count.lock().expect("lock should not be poisoned") += 1;
        Ok(BTreeMap::from([(
            "e2e_config_source".into(),
            r#"{"schedule":{}}"#.into(),
        )]))
    };

    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_config_ext", osquery_socket())
            .expect("server should create");
        server
            .register_plugin(ConfigPlugin::new("e2e_config", generate))
            .expect("register should succeed");
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    // Verify registration by checking the extensions list
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");
    let extensions = client.extensions().expect("extensions should succeed");
    assert!(
        !extensions.is_empty(),
        "at least one extension should be registered"
    );

    // Verify our extension is listed
    let our_ext = extensions
        .values()
        .find(|info| info.name.as_deref() == Some("e2e_config_ext"));
    assert!(
        our_ext.is_some(),
        "e2e_config_ext should be in the extensions list"
    );

    drop(handle);
}

// ---------------------------------------------------------------------------
// 4. Server + LoggerPlugin: register and verify
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn logger_plugin_e2e() {
    let logs = Arc::new(Mutex::new(Vec::<(LogType, String)>::new()));

    let log_fn = move |typ: LogType, msg: &str| -> Result<()> {
        logs.lock()
            .expect("lock should not be poisoned")
            .push((typ, msg.to_string()));
        Ok(())
    };

    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_logger_ext", osquery_socket())
            .expect("server should create");
        server
            .register_plugin(LoggerPlugin::new("e2e_logger", log_fn))
            .expect("register should succeed");
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    // Verify registration via extensions list
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");
    let extensions = client.extensions().expect("extensions should succeed");

    let our_ext = extensions
        .values()
        .find(|info| info.name.as_deref() == Some("e2e_logger_ext"));
    assert!(
        our_ext.is_some(),
        "e2e_logger_ext should be in the extensions list"
    );

    drop(handle);
}

// ---------------------------------------------------------------------------
// 5. Server + DistributedPlugin: register and verify
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn distributed_plugin_e2e() {
    let get_queries = || -> Result<QueriesRequest> {
        Ok(QueriesRequest::new(BTreeMap::from([(
            "e2e_query".into(),
            "SELECT 1".into(),
        )])))
    };

    let write_results = |_results: Vec<QueryResponse>| -> Result<()> { Ok(()) };

    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_distributed_ext", osquery_socket())
            .expect("server should create");
        server
            .register_plugin(DistributedPlugin::new(
                "e2e_distributed",
                get_queries,
                write_results,
            ))
            .expect("register should succeed");
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    // Verify registration via extensions list
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");
    let extensions = client.extensions().expect("extensions should succeed");

    let our_ext = extensions
        .values()
        .find(|info| info.name.as_deref() == Some("e2e_distributed_ext"));
    assert!(
        our_ext.is_some(),
        "e2e_distributed_ext should be in the extensions list"
    );

    drop(handle);
}

// ---------------------------------------------------------------------------
// 6. Server with multiple plugins via register_plugins
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn register_multiple_plugins_e2e() {
    let handle = std::thread::spawn(move || {
        let mut server = ExtensionManagerServer::new("e2e_multi_ext", osquery_socket())
            .expect("server should create");

        let table = TablePlugin::new(
            "e2e_multi_table",
            vec![ColumnDefinition::text("col1")],
            |_ctx| Ok(vec![BTreeMap::from([("col1".into(), "val1".into())])]),
        );

        let config = ConfigPlugin::new("e2e_multi_config", || {
            Ok(BTreeMap::from([("src".into(), "{}".into())]))
        });

        let plugins: Vec<Box<dyn osquery_rs_sdk::OsqueryPlugin>> =
            vec![Box::new(table), Box::new(config)];

        server
            .register_plugins(plugins)
            .expect("register_plugins should succeed");

        let _ = server.run();
    });

    std::thread::sleep(Duration::from_secs(2));

    // Query the table through osqueryd
    let mut client =
        ExtensionManagerClient::connect_with_path(osquery_socket()).expect("should connect");

    let rows = client
        .query_rows("SELECT * FROM e2e_multi_table")
        .expect("should query multi table");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("col1").map(String::as_str), Some("val1"));

    // Verify both plugins are registered
    let extensions = client.extensions().expect("extensions should succeed");
    let our_ext = extensions
        .values()
        .find(|info| info.name.as_deref() == Some("e2e_multi_ext"));
    assert!(
        our_ext.is_some(),
        "e2e_multi_ext should be in the extensions list"
    );

    drop(handle);
}

// ---------------------------------------------------------------------------
// 7. Builder pattern with custom options
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a running osqueryd extension socket"]
fn builder_pattern_e2e() {
    // Verify the builder compiles and connects successfully
    let _server = ExtensionManagerServer::builder("e2e_builder_ext", osquery_socket())
        .version("1.0.0")
        .timeout(Duration::from_secs(3))
        .ping_interval(Duration::from_secs(5))
        .build()
        .expect("builder should succeed");
}

// ---------------------------------------------------------------------------
// 8. MockExtensionManager: test without live osqueryd
// ---------------------------------------------------------------------------

#[cfg(feature = "mock")]
#[test]
fn mock_server_with_mock_client() {
    use osquery_rs_sdk::mock::MockExtensionManager;

    let mock = MockExtensionManager::new();
    let mut server = ExtensionManagerServer::builder("mock_ext", "/tmp/mock_socket.em")
        .client(Box::new(mock))
        .build()
        .expect("builder with mock client should succeed");

    let table = TablePlugin::new("mock_table", vec![ColumnDefinition::text("name")], |_ctx| {
        Ok(vec![BTreeMap::from([("name".into(), "test".into())])])
    });

    server
        .register_plugin(table)
        .expect("register should succeed");

    // Shutdown should be a no-op (never started, no uuid)
    server
        .shutdown()
        .expect("shutdown without start should succeed");
}

// ---------------------------------------------------------------------------
// 9. Error cases (no live osqueryd needed)
// ---------------------------------------------------------------------------

#[test]
fn socket_path_too_long() {
    let long_path = "a".repeat(200) + ".em";
    let result = ExtensionManagerServer::new("test", &long_path);
    assert!(result.is_err(), "socket path too long should error");
}

#[cfg(feature = "mock")]
#[test]
fn duplicate_plugin_registration() {
    use osquery_rs_sdk::mock::MockExtensionManager;

    let mock = MockExtensionManager::new();
    let mut server = ExtensionManagerServer::builder("dup_ext", "/tmp/dup_socket.em")
        .client(Box::new(mock))
        .build()
        .expect("builder should succeed");

    let table1 = TablePlugin::new("same_name", vec![ColumnDefinition::text("a")], |_ctx| {
        Ok(vec![])
    });
    let table2 = TablePlugin::new("same_name", vec![ColumnDefinition::text("b")], |_ctx| {
        Ok(vec![])
    });

    server
        .register_plugin(table1)
        .expect("first register should succeed");
    let err = server.register_plugin(table2);
    assert!(err.is_err(), "duplicate plugin name should error");
    assert!(
        err.unwrap_err().to_string().contains("already registered"),
        "error should mention 'already registered'"
    );
}

#[test]
fn client_connect_to_nonexistent_socket() {
    let result = ExtensionManagerClient::connect_with_path("/tmp/nonexistent_e2e_test.em");
    assert!(
        result.is_err(),
        "connecting to nonexistent socket should fail"
    );
}

#[test]
fn client_connect_with_timeout_to_nonexistent_socket() {
    let result = ExtensionManagerClient::connect_with_timeout(
        "/tmp/nonexistent_e2e_timeout.em",
        Duration::from_millis(300),
    );
    assert!(
        result.is_err(),
        "connect_with_timeout to nonexistent socket should fail"
    );
}
