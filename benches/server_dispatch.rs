#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::needless_pass_by_value
)]

//! Criterion benchmarks for server dispatch and thrift round-trip throughput.
//!
//! These benchmarks measure the full request cycle: thrift binary encode →
//! UDS write → UDS read → thrift decode → handler dispatch → thrift encode →
//! UDS write → UDS read → thrift decode.
//!
//! The server runs in a background thread with a [`MockExtensionManager`]
//! client, so no live osqueryd is required.
//!
//! Run with:
//! ```sh
//! cargo bench --bench server_dispatch
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use osquery_rs_sdk::mock::MockExtensionManager;
use osquery_rs_sdk::{
    ColumnDefinition, ExtensionManagerClient, ExtensionManagerServer, TablePlugin,
};

/// Set up a server with a trivial table plugin and return:
/// - the `JoinHandle` for the server thread (which runs `server.run()`)
/// - a [`ShutdownHandle`] to stop it
/// - the listen socket path to connect a client to
///
/// The server runs on a unique UDS path derived from `tag` to avoid
/// interference between benchmarks.
fn start_server(
    tag: &str,
) -> (
    std::thread::JoinHandle<()>,
    osquery_rs_sdk::ShutdownHandle,
    String,
) {
    let socket = format!("/tmp/osquery_bench_{tag}.em");
    // Mock returns uuid=1, so the extension server listens on socket_path.1
    let listen_socket = format!("{socket}.1");

    // Clean up stale sockets from prior runs
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&listen_socket);

    let mock = MockExtensionManager::new();
    let mut server = ExtensionManagerServer::builder(tag, &socket)
        .client(Box::new(mock))
        .build()
        .expect("server builder should succeed");

    let table = TablePlugin::new(
        "bench_table",
        vec![ColumnDefinition::text("name")],
        |_ctx| Ok(vec![BTreeMap::from([("name".into(), "bench".into())])]),
    );
    server
        .register_plugin(table)
        .expect("register_plugin should succeed");

    let shutdown = server.shutdown_handle();
    let handle = std::thread::spawn(move || {
        // run() blocks until shutdown is requested
        let _ = server.run();
    });

    // Wait for the server to start listening
    for _ in 0..50 {
        if std::path::Path::new(&listen_socket).exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        std::path::Path::new(&listen_socket).exists(),
        "server did not create listen socket at {listen_socket}"
    );

    (handle, shutdown, listen_socket)
}

/// Benchmark: thrift ping round-trip through UDS.
///
/// Measures the full path: client thrift encode → UDS → server thrift decode →
/// handler dispatch (ping handler) → server thrift encode → UDS → client
/// thrift decode.
fn bench_ping_roundtrip(c: &mut Criterion) {
    let (handle, shutdown, listen_socket) = start_server("ping_rt");
    let mut client = ExtensionManagerClient::connect_with_path(&listen_socket)
        .expect("client should connect to bench server");

    // Warm up: verify the path works
    client.ping().expect("warm-up ping should succeed");

    c.bench_function("thrift_ping_roundtrip", |b| {
        b.iter(|| {
            let _ = black_box(client.ping());
        });
    });

    // Clean shutdown
    shutdown.shutdown();
    handle.join().ok();
}

/// Benchmark: sustained ping throughput (batch of N pings per iteration).
fn bench_ping_throughput(c: &mut Criterion) {
    let (handle, shutdown, listen_socket) = start_server("ping_tp");
    let mut client = ExtensionManagerClient::connect_with_path(&listen_socket)
        .expect("client should connect to bench server");

    client.ping().expect("warm-up ping should succeed");

    let mut group = c.benchmark_group("ping_throughput");
    group.throughput(criterion::Throughput::Elements(100));
    group.bench_function("100_pings", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let _ = black_box(client.ping());
            }
        });
    });
    group.finish();

    shutdown.shutdown();
    handle.join().ok();
}

/// Benchmark: concurrent ping throughput with N parallel clients.
///
/// Each iteration spawns `n_clients` threads, each performing 100 pings.
/// Measures aggregate throughput and contention characteristics.
fn bench_concurrent_ping(c: &mut Criterion) {
    let (handle, shutdown, listen_socket) = start_server("conc_ping");

    // Verify connectivity
    {
        let mut probe = ExtensionManagerClient::connect_with_path(&listen_socket)
            .expect("probe should connect");
        probe.ping().expect("probe ping should succeed");
        probe.close();
    }

    let mut group = c.benchmark_group("concurrent_ping");

    for n_clients in [1, 2, 4, 8, 16] {
        let pings_per_client: u64 = 100;
        let total_pings = n_clients as u64 * pings_per_client;
        group.throughput(criterion::Throughput::Elements(total_pings));

        group.bench_with_input(
            BenchmarkId::new("clients", n_clients),
            &n_clients,
            |b, &n| {
                b.iter(|| {
                    let barrier = Arc::new(Barrier::new(n + 1));
                    let mut handles = Vec::with_capacity(n);

                    for _ in 0..n {
                        let sock = listen_socket.clone();
                        let bar = barrier.clone();
                        handles.push(std::thread::spawn(move || {
                            let mut client =
                                ExtensionManagerClient::connect_with_path(&sock).unwrap();
                            bar.wait(); // synchronize start
                            for _ in 0..pings_per_client {
                                let _ = black_box(client.ping());
                            }
                            client.close();
                        }));
                    }

                    barrier.wait(); // release all clients simultaneously
                    for h in handles {
                        h.join().unwrap();
                    }
                });
            },
        );
    }
    group.finish();

    // Shutdown
    shutdown.shutdown();
    handle.join().ok();
}

criterion_group!(
    benches,
    bench_ping_roundtrip,
    bench_ping_throughput,
    bench_concurrent_ping
);
criterion_main!(benches);
