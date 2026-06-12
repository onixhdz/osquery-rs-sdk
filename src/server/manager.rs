use super::{
    OsqueryPlugin, RegistryName,
    threaded::{ExtensionServer, StopHandle},
};
use crate::{Error, Result, client, osquery};
use std::path::PathBuf;
use std::sync::mpsc;
use std::{
    collections::HashMap,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
    time,
};

/// Map of plugin name → plugin for a single registry.
type Plugins = HashMap<String, Arc<Mutex<Box<dyn OsqueryPlugin>>>>;

/// Maps each [`RegistryName`] to its plugins.
type Registry = Arc<Mutex<HashMap<RegistryName, Plugins>>>;

/// Sender half of the shutdown signal channel.
type ShutdownSignal = mpsc::SyncSender<Option<Error>>;

/// Default timeout for connecting to the osquery socket.
const DEFAULT_TIMEOUT: time::Duration = time::Duration::from_secs(1);

/// Default interval for pinging osquery to check connectivity.
const DEFAULT_PING_INTERVAL: time::Duration = time::Duration::from_secs(5);

/// How long shutdown waits for the osquery client lock before proceeding
/// without it. An in-flight RPC wedged on a hung osquery connection holds
/// the lock indefinitely; teardown must stay bounded regardless.
const CLIENT_LOCK_DEADLINE: time::Duration = time::Duration::from_secs(1);

/// A lightweight handle that can trigger a full shutdown of an
/// [`ExtensionManagerServer`] from any thread.
///
/// This handle is `Clone + Send + Sync`, so it can be freely shared across
/// threads, signal handlers, or async tasks. Calling [`shutdown`](ShutdownHandle::shutdown)
/// causes the server's [`run`](ExtensionManagerServer::run) (or
/// [`run_with_signal_handling`](ExtensionManagerServer::run_with_signal_handling))
/// loop to initiate the full clean shutdown sequence: deregister the extension
/// from osquery, stop the listener, and close the client connection.
///
/// # Example
/// ```no_run
/// use osquery_rs_sdk::ExtensionManagerServer;
///
/// let server = ExtensionManagerServer::new("my_ext", "/var/osquery/osquery.em").unwrap();
/// let handle = server.shutdown_handle();
///
/// // Send to another thread, signal handler, etc.
/// std::thread::spawn(move || {
///     // ... some condition ...
///     handle.shutdown();
/// });
/// ```
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    sender: ShutdownSignal,
}

impl ShutdownHandle {
    /// Trigger a full shutdown of the extension manager server.
    ///
    /// This sends a shutdown signal that causes `run()` or
    /// `run_with_signal_handling()` to initiate the clean shutdown sequence
    /// (deregister extension, stop listener, close client).
    ///
    /// This method is safe to call multiple times; subsequent calls are no-ops
    /// (the channel is bounded to 1, so extra sends silently fail).
    pub fn shutdown(&self) {
        self.sender.try_send(None).ok();
    }
}

/// Whether the server owns the osquery client and should close it on shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientOwnership {
    /// Server created the client; it will be closed on shutdown.
    Owned,
    /// Caller provided the client; the server will not close it.
    Borrowed,
}

/// Maximum characters allowed in a socket path. A UUID suffix (e.g., ".12345")
/// is appended downstream, which could exceed the Unix socket path limit of
/// ~103 characters.
/// See: <https://unix.stackexchange.com/questions/367008/why-is-socket-path-length-limited-to-a-hundred-chars>
pub(crate) const MAX_SOCKET_PATH_CHARACTERS: usize = 97;

/// Builder for constructing an [`ExtensionManagerServer`] with custom configuration.
///
/// # Example
/// ```no_run
/// use osquery_rs_sdk::ExtensionManagerServer;
/// use std::time::Duration;
///
/// let server = ExtensionManagerServer::builder("my_ext", "/var/osquery/osquery.em")
///     .version("1.0.0")
///     .ping_interval(Duration::from_secs(10))
///     .build()
///     .unwrap();
/// ```
pub struct ExtensionManagerServerBuilder<P: AsRef<Path>> {
    name: String,
    socket_path: P,
    version: Option<String>,
    timeout: time::Duration,
    ping_interval: time::Duration,
    client: Option<Box<dyn client::ExtensionManager>>,
}

impl<P: AsRef<Path>> fmt::Debug for ExtensionManagerServerBuilder<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionManagerServerBuilder")
            .field("name", &self.name)
            .field("socket_path", &self.socket_path.as_ref())
            .field("version", &self.version)
            .field("timeout", &self.timeout)
            .field("ping_interval", &self.ping_interval)
            .field("client", &self.client.is_some())
            .finish()
    }
}

impl<P: AsRef<Path>> ExtensionManagerServerBuilder<P> {
    fn new(name: &str, socket_path: P) -> Self {
        Self {
            name: name.to_string(),
            socket_path,
            version: None,
            timeout: DEFAULT_TIMEOUT,
            ping_interval: DEFAULT_PING_INTERVAL,
            client: None,
        }
    }

    /// Set the extension version string reported to osquery.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set how long to wait for the osquery socket to appear before
    /// connecting. Useful when the extension starts before `osqueryd`
    /// has created its socket.
    #[must_use]
    pub fn timeout(mut self, timeout: time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set how often the extension pings osquery to check connectivity.
    #[must_use]
    pub fn ping_interval(mut self, interval: time::Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Use an existing client instead of creating a new one.
    /// When set, the server will not shut down the client on server shutdown.
    #[must_use]
    pub fn client(mut self, client: Box<dyn client::ExtensionManager>) -> Self {
        self.client = Some(client);
        self
    }

    /// Build the [`ExtensionManagerServer`], connecting to the osquery socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket path exceeds `MAX_SOCKET_PATH_CHARACTERS`,
    /// if the socket does not appear within the configured timeout, or if
    /// connecting to the `osqueryd` socket fails.
    pub fn build(self) -> Result<ExtensionManagerServer> {
        let path = self.socket_path.as_ref();
        let path_len = path.as_os_str().len();
        if path_len > MAX_SOCKET_PATH_CHARACTERS {
            return Err(format!(
                "socket path {} ({} characters) exceeded the maximum socket path character length of {}",
                path.display(),
                path_len,
                MAX_SOCKET_PATH_CHARACTERS
            )
            .into());
        }

        let (osquery_client, client_ownership) = if let Some(c) = self.client {
            (c, ClientOwnership::Borrowed)
        } else {
            let c = client::ExtensionManagerClient::connect_with_timeout(
                &self.socket_path,
                self.timeout,
            )?;
            let owned: Box<dyn client::ExtensionManager> = Box::new(c);
            (owned, ClientOwnership::Owned)
        };

        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);

        Ok(ExtensionManagerServer {
            name: self.name,
            registry: Arc::from(Mutex::new(HashMap::new())),
            socket_path: path.to_path_buf(),
            osquery_client: Arc::from(Mutex::new(Some(osquery_client))),
            client_ownership,
            uuid: None,
            server_stop_handle: None,
            version: self.version,
            listen_path: None,
            ping_interval: self.ping_interval,
            shutdown_tx,
            shutdown_rx: Some(shutdown_rx),
        })
    }
}

/// `ExtensionManagerServer` is an implementation of the full `ExtensionManager`
/// API. Plugins can register with an extension manager, which handles the
/// communication with the osquery process.
pub struct ExtensionManagerServer {
    name: String,
    version: Option<String>,
    osquery_client: Arc<Mutex<Option<Box<dyn client::ExtensionManager>>>>,
    client_ownership: ClientOwnership,
    registry: Registry,
    socket_path: PathBuf,
    listen_path: Option<PathBuf>,
    uuid: Option<osquery::ExtensionRouteUUID>,
    server_stop_handle: Option<StopHandle>,
    ping_interval: time::Duration,
    shutdown_tx: ShutdownSignal,
    shutdown_rx: Option<mpsc::Receiver<Option<Error>>>,
}

impl fmt::Debug for ExtensionManagerServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionManagerServer")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("socket_path", &self.socket_path)
            .field("listen_path", &self.listen_path)
            .field("uuid", &self.uuid)
            .field("client_ownership", &self.client_ownership)
            .field("ping_interval", &self.ping_interval)
            .finish_non_exhaustive()
    }
}

impl ExtensionManagerServer {
    /// Create a new extension management server communicating with osquery
    /// over the socket at the provided path. Waits up to one second for the
    /// socket to appear (extensions often start before `osqueryd` has created
    /// it), then connects.
    ///
    /// For additional configuration (version, timeout, ping interval, custom client),
    /// use [`builder`](Self::builder) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket does not appear in time or if connecting
    /// to the `osqueryd` socket at `socket_path` fails.
    pub fn new<P: AsRef<Path>>(name: &str, socket_path: P) -> Result<Self> {
        Self::builder(name, socket_path).build()
    }

    /// Return a builder for constructing an `ExtensionManagerServer` with custom options.
    pub fn builder<P: AsRef<Path>>(name: &str, socket_path: P) -> ExtensionManagerServerBuilder<P> {
        ExtensionManagerServerBuilder::new(name, socket_path)
    }

    /// Return the extension uuid assigned by osquery after registration.
    #[must_use]
    pub fn uuid(&self) -> Option<osquery::ExtensionRouteUUID> {
        self.uuid
    }

    /// Add an `OsqueryPlugin` to this extension manager registry.
    ///
    /// # Errors
    ///
    /// Returns an error if a plugin with the same name and registry already exists,
    /// or if the registry lock is poisoned.
    pub fn register_plugin(&mut self, plugin: impl OsqueryPlugin + 'static) -> Result<()> {
        let name = plugin.name().to_string();
        let registry_name = plugin.registry_name();
        let mut registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;
        let plugins = registry.entry(registry_name).or_default();
        if plugins.contains_key(&name) {
            return Err(format!(
                "plugin \"{name}\" already registered in {registry_name} registry"
            )
            .into());
        }
        plugins.insert(name, Arc::new(Mutex::new(Box::new(plugin))));
        Ok(())
    }

    /// Add multiple [`OsqueryPlugin`]s to this extension manager registry.
    ///
    /// # Errors
    ///
    /// Returns an error if any plugin has a duplicate name or if the registry lock is poisoned.
    pub fn register_plugins(
        &mut self,
        plugins: impl IntoIterator<Item = Box<dyn OsqueryPlugin>>,
    ) -> Result<()> {
        let mut registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;
        for plugin in plugins {
            let name = plugin.name().to_string();
            let registry_name = plugin.registry_name();
            let entries = registry.entry(registry_name).or_default();
            if entries.contains_key(&name) {
                return Err(format!(
                    "plugin \"{name}\" already registered in {registry_name} registry"
                )
                .into());
            }
            entries.insert(name, Arc::new(Mutex::new(plugin)));
        }
        Ok(())
    }

    fn gen_registry(&mut self) -> Result<osquery::ExtensionRegistry> {
        let mut ext_registry = osquery::ExtensionRegistry::new();
        let registry = self.registry.lock().map_err(|_| "registry lock poisoned")?;

        for (reg_name, plugins) in registry.iter() {
            let routes = ext_registry.entry(reg_name.to_string()).or_default();
            for (plug_name, plugin) in plugins {
                let plugin = plugin.lock().map_err(|_| "plugin lock poisoned")?;
                routes
                    .entry(plug_name.clone())
                    .or_insert_with(|| plugin.routes());
            }
        }

        Ok(ext_registry)
    }

    /// Register the extension and plugins.
    /// All plugins should be registered with `register_plugin()` before calling this method.
    /// Returns the `ExtensionRouteUUID`.
    fn register_extension(&mut self) -> Result<i64> {
        let registry = self.gen_registry()?;
        let response = self
            .osquery_client
            .lock()
            .map_err(|_| "osquery client lock poisoned")?
            .as_mut()
            .ok_or("cannot start, shutdown in progress")?
            .register_extension(
                osquery::InternalExtensionInfo::new(
                    self.name.clone(),
                    self.version.clone(),
                    None,
                    None,
                ),
                registry,
            )?;

        let code = response.code.unwrap_or_default();
        if code != 0 {
            return Err(format!(
                "status {} registering extension: {}",
                code,
                response.message.unwrap_or_default()
            )
            .into());
        }

        self.uuid = response.uuid;
        let uuid = self.uuid.ok_or("uuid returned nil")?;

        // osquery expects the extension to listen on `<socket_path>.<uuid>`.
        let mut listen_path = self.socket_path.clone().into_os_string();
        listen_path.push(format!(".{uuid}"));
        self.listen_path = Some(PathBuf::from(listen_path));
        Ok(uuid)
    }

    /// Open a new thread and begin listening for requests from the osquery process.
    /// All plugins should be registered with `register_plugin()` before calling `start()`.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    fn start(&mut self) -> Result<()> {
        self.register_extension()?;

        let listen_path = self
            .listen_path
            .clone()
            .ok_or("set the listen_path to start server")?;

        let shutdown = self.shutdown_tx.clone();
        let handler = ExtensionServerHandler {
            registry: self.registry.clone(),
            shutdown: shutdown.clone(),
        };
        let processor = osquery::ExtensionSyncProcessor::new(handler);
        let mut server = ExtensionServer::new(processor)?;

        // Store the stop handle so shutdown() can stop the listener
        self.server_stop_handle = Some(server.stop_handle());

        std::thread::spawn(move || {
            if let Err(err) = server.listen(&listen_path) {
                let _ = shutdown.send(Some(err.into()));
            }
        });

        Ok(())
    }

    /// Try to acquire the osquery client lock, giving up after `deadline`
    /// so a wedged in-flight RPC cannot block the caller indefinitely.
    /// Returns `None` on timeout or a poisoned lock.
    fn try_lock_client(
        &self,
        deadline: time::Duration,
    ) -> Option<std::sync::MutexGuard<'_, Option<Box<dyn client::ExtensionManager>>>> {
        let give_up = time::Instant::now() + deadline;
        loop {
            match self.osquery_client.try_lock() {
                Ok(guard) => return Some(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => return None,
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if time::Instant::now() >= give_up {
                return None;
            }
            std::thread::sleep(time::Duration::from_millis(10));
        }
    }

    /// Deregister the extension, stop the server, notify plugins via
    /// [`OsqueryPlugin::shutdown`], and close all sockets.
    ///
    /// Teardown is best-effort and bounded: if the osquery client is wedged
    /// in an RPC (e.g. a ping blocked on a hung connection), deregistration
    /// and client close are skipped rather than waiting forever.
    /// This method is idempotent: calling it multiple times is safe and will
    /// not return an error on subsequent calls.
    ///
    /// # Errors
    ///
    /// Currently never fails; the `Result` is kept for API stability.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn shutdown(&mut self) -> Result<()> {
        let Some(uuid) = self.uuid.take() else {
            return Ok(());
        };

        match self.try_lock_client(CLIENT_LOCK_DEADLINE) {
            Some(mut client_guard) => {
                if let Some(client) = client_guard.as_mut() {
                    match client.deregister_extension(uuid) {
                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!("error deregistering extension {}: {}", uuid, err);
                            #[cfg(not(feature = "tracing"))]
                            let _ = err;
                        }
                        Ok(res) if res.code.unwrap_or_default() != 0 => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                "status {} deregistering extension: {}",
                                res.code.unwrap_or_default(),
                                res.message.as_deref().unwrap_or_default()
                            );
                        }
                        Ok(_) => {}
                    }
                }
            }
            None => {
                #[cfg(feature = "tracing")]
                tracing::warn!("skipping deregistration: osquery client unavailable");
            }
        }

        if let Some(stop_handle) = self.server_stop_handle.take() {
            stop_handle.stop();
        }

        if let Ok(registry) = self.registry.lock() {
            for plugins in registry.values() {
                for plugin in plugins.values() {
                    if let Ok(plugin) = plugin.lock() {
                        plugin.shutdown();
                    }
                }
            }
        }

        if self.client_ownership == ClientOwnership::Owned {
            match self.try_lock_client(CLIENT_LOCK_DEADLINE) {
                Some(mut client_guard) => {
                    if let Some(client) = client_guard.as_mut() {
                        client.close();
                    }
                    *client_guard = None;
                }
                None => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("skipping client close: osquery client unavailable");
                }
            }
        }

        Ok(())
    }

    /// Return a [`ShutdownHandle`] that can be used to trigger a full shutdown
    /// of the extension manager server from any thread.
    ///
    /// The returned handle is `Clone + Send + Sync`, so it can be freely shared.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            sender: self.shutdown_tx.clone(),
        }
    }

    /// Start the extension manager and run until osquery calls for a shutdown
    /// or the osquery instance goes away.
    /// Takes `&mut self` instead of consuming `self` so that external code
    /// (e.g., signal handlers) can call [`shutdown`](Self::shutdown) concurrently.
    ///
    /// # Errors
    ///
    /// Returns an error if starting the server fails, if the osquery process
    /// goes away (ping failure), or if shutdown encounters an error.
    /// Returns an error if called more than once (the internal receiver is consumed
    /// on the first call).
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), fields(name = %self.name))
    )]
    pub fn run(&mut self) -> Result<()> {
        let rx = self
            .shutdown_rx
            .take()
            .ok_or("run() has already been called")?;
        let tx = self.shutdown_tx.clone();
        let ping_interval = self.ping_interval;
        let osquery_client = self.osquery_client.clone();

        self.start()?;

        // Watch for the osquery process going away. If so, initiate shutdown.
        // The thread sleeps on `ping_stop_rx` so it can be interrupted
        // promptly when `run` begins its shutdown sequence.
        let (ping_stop_tx, ping_stop_rx) = mpsc::channel::<()>();
        let (ping_done_tx, ping_done_rx) = mpsc::channel::<()>();
        let ping_thread = std::thread::spawn(move || {
            'watch: loop {
                match ping_stop_rx.recv_timeout(ping_interval) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break 'watch,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }

                let Ok(mut guard) = osquery_client.lock() else {
                    tx.send(Some(Error::from("could not lock osquery client for ping")))
                        .ok();
                    break 'watch;
                };
                // Client was cleared by shutdown -- nothing left to watch.
                let Some(client) = guard.as_mut() else {
                    break 'watch;
                };
                match client.ping() {
                    Err(e) => {
                        tx.send(Some(Error::from(e).context("extension ping failed")))
                            .ok();
                        break 'watch;
                    }
                    Ok(status) if status.code.unwrap_or_default() != 0 => {
                        tx.send(Some(Error::from(format!(
                            "ping returned status {}",
                            status.code.unwrap_or_default()
                        ))))
                        .ok();
                        break 'watch;
                    }
                    Ok(_) => {}
                }
            }
            ping_done_tx.send(()).ok();
        });

        let stop_signal = rx.recv();
        // Stop the ping watcher before tearing down so it does not race
        // shutdown for the client lock, then collect it once shutdown
        // finishes. The wait is bounded: a thread wedged inside a blocking
        // RPC is detached instead of hanging run().
        ping_stop_tx.send(()).ok();
        let shutdown_result = self.shutdown();
        match ping_done_rx.recv_timeout(CLIENT_LOCK_DEADLINE) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = ping_thread.join();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                #[cfg(feature = "tracing")]
                tracing::warn!("detaching ping thread wedged in an osquery RPC");
            }
        }

        shutdown_result.and_then(move |()| match stop_signal {
            Ok(Some(err)) => Err(err),
            Err(_) => Err("shutdown signal error".into()),
            Ok(None) => Ok(()),
        })
    }

    /// Start the extension manager with automatic OS signal handling.
    ///
    /// This is a convenience wrapper around [`run`](Self::run) that spawns a
    /// background thread to listen for termination signals (SIGINT + SIGTERM on
    /// Unix, Ctrl+C on Windows). When a signal is received, the server performs
    /// a full clean shutdown (deregister, stop listener, close client).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`run`](Self::run), plus any errors from
    /// setting up the signal handlers.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), fields(name = %self.name))
    )]
    pub fn run_with_signal_handling(&mut self) -> Result<()> {
        let signal_tx = self.shutdown_tx.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    signal_tx.send(Some(Error::from(e))).ok();
                    return;
                }
            };
            rt.block_on(async move {
                match wait_for_shutdown_signal().await {
                    Ok(()) => {
                        signal_tx.send(None).ok();
                    }
                    Err(e) => {
                        signal_tx.send(Some(e)).ok();
                    }
                }
            });
        });
        self.run()
    }
}

impl Drop for ExtensionManagerServer {
    fn drop(&mut self) {
        // Best-effort shutdown; ignore errors since we're in Drop
        let _ = self.shutdown();
    }
}

/// Thrift request handler for the extension server.
struct ExtensionServerHandler {
    registry: Registry,
    shutdown: ShutdownSignal,
}

impl osquery::ExtensionSyncHandler for ExtensionServerHandler {
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self), level = "debug"))]
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, request), fields(registry = %registry, item = %item))
    )]
    fn handle_call(
        &self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        // Phase 1: Lookup (holds registry lock briefly, then releases)
        let lookup_result = {
            let reg_name: super::RegistryName = match registry.parse() {
                Ok(r) => r,
                Err(msg) => {
                    return Ok(osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(1, msg, None),
                        None,
                    ));
                }
            };
            let reg = self.registry.lock().map_err(|_| "registry lock poisoned")?;
            match reg.get(&reg_name) {
                None => Err(format!("Unknown registry: {registry}")),
                Some(subreg) => match subreg.get(item.as_str()) {
                    None => Err(format!("Unknown registry item: {item}")),
                    Some(p) => Ok(Arc::clone(p)),
                },
            }
        }; // registry lock dropped here

        // Phase 2: Execute (no registry lock held — other plugins can run concurrently)
        match lookup_result {
            Ok(plugin) => {
                let mut plugin = plugin.lock().map_err(|_| "plugin lock poisoned")?;
                Ok(plugin.call(request))
            }
            Err(msg) => {
                #[cfg(feature = "tracing")]
                tracing::warn!("{}", msg);
                Ok(osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(1, msg, None),
                    None,
                ))
            }
        }
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        self.shutdown
            .send(None)
            .map_err(|_| "could not send shutdown signal".into())
    }
}

/// Wait for an OS termination signal.
///
/// On Unix, listens for SIGINT (Ctrl+C) and SIGTERM concurrently.
/// On Windows, listens for Ctrl+C.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::from(e).context("failed to register SIGTERM handler"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|e| Error::from(e).context("failed to wait for SIGINT"))?;
        }
        _ = sigterm.recv() => {}
    }
    Ok(())
}

/// Wait for an OS termination signal.
///
/// On Windows, listens for Ctrl+C.
#[cfg(windows)]
async fn wait_for_shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| Error::from(e).context("failed to wait for Ctrl+C"))?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::osquery::ExtensionSyncHandler;
    use crate::plugin::table::{ColumnDefinition, TablePlugin};
    use crate::server::RegistryName;
    use crate::server::mock;
    use serial_test::serial;

    #[cfg(unix)]
    const DEFAULT_TEST_SOCKET: &str = "/var/osquery/osquery.em";
    #[cfg(windows)]
    const DEFAULT_TEST_SOCKET: &str = r"\\.\pipe\osquery.em";

    /// Path to the osqueryd extension socket, overridable via `OSQUERY_SOCKET`
    /// so ignored tests can run against an unprivileged osqueryd instance.
    fn test_socket() -> String {
        std::env::var("OSQUERY_SOCKET").unwrap_or_else(|_| DEFAULT_TEST_SOCKET.to_string())
    }

    fn init_server() -> ExtensionManagerServer {
        let mut server = ExtensionManagerServer::new("test_server", test_socket()).unwrap();
        server.ping_interval = std::time::Duration::from_secs(1);
        server
    }

    fn wait_for_extension_server<P: AsRef<std::path::Path>>(path: P) {
        for _ in 0..50 {
            if let Ok(mut client) = client::ExtensionManagerClient::connect_with_path(&path) {
                if client.ping().is_ok() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        panic!(
            "timed out waiting for extension server at {}",
            path.as_ref().display()
        );
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_plugin() {
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();

        server
            .registry
            .lock()
            .unwrap()
            .get(&RegistryName::Table)
            .expect("plugin not found in table registry found")
            .get(name);
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn gen_registry() {
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();
        let registry = server.gen_registry().unwrap();
        assert!(
            registry.contains_key("table"),
            "test_plugin should in registry"
        );
        assert!(
            registry.get("table").unwrap().contains_key("test_plugin"),
            "test_plugin should in registry"
        )
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_extension() {
        let plugin = TablePlugin::new(
            "test_register_ext",
            vec![ColumnDefinition::text("col1")],
            |_ctx| Ok(vec![]),
        );
        let mut server = init_server();

        server.register_plugin(plugin).unwrap();
        let uuid = server.register_extension();

        assert!(
            uuid.is_ok(),
            "extension plugin should be in registry: {:?}",
            uuid.err()
        );
        assert!(
            server.uuid.is_some(),
            "uuid should be set by register_extension"
        );
        assert!(
            server.listen_path.is_some(),
            "listen_path should be set by register_extension"
        )
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn start() {
        let mut server = init_server();
        server.start().unwrap();
        let listen_path = server.listen_path.clone().unwrap();
        wait_for_extension_server(&listen_path);
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn shutdown() {
        let mut server = init_server();

        assert!(
            server.shutdown().is_ok(),
            "shutdown without uuid should succeed (idempotent)"
        );

        server.start().unwrap();

        let listen_path = server.listen_path.clone().unwrap();
        wait_for_extension_server(&listen_path);

        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "shutdown should be ok: {shutdown_err:?}"
        );

        let shutdown_err = server.shutdown().err();
        assert!(
            shutdown_err.is_none(),
            "second shutdown should be ok (idempotent): {shutdown_err:?}"
        );
    }

    #[test]
    fn handle_shutdown() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handler = ExtensionServerHandler {
            registry: Arc::from(Mutex::new(HashMap::new())),
            shutdown: tx,
        };
        std::thread::spawn(move || handler.handle_shutdown());
        assert!(rx.recv().unwrap().is_none(), "shutdown should not fail");
    }

    #[test]
    fn handle_call() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let reg: Registry = Arc::from(Mutex::new(HashMap::new()));
        let handler = ExtensionServerHandler {
            registry: reg.clone(),
            shutdown: tx,
        };
        let res = handler
            .handle_call(
                String::from("table"),
                String::new(),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().code.unwrap(),
            1,
            "status code should be 1 if table not found"
        );
        let name = "test_plugin";
        let plugin = mock::MockPlugin::new(name, RegistryName::Table);
        let plugin_name = plugin.name().to_string();

        reg.lock()
            .unwrap()
            .entry(RegistryName::Table)
            .or_default()
            .entry(plugin_name)
            .or_insert_with(|| Arc::new(Mutex::new(Box::new(plugin))));

        let res = handler
            .handle_call(
                String::from("table"),
                name.to_string(),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().code.unwrap(),
            mock::STATUS_CODE,
            "status code should be 1 if table not found"
        );

        let res = handler
            .handle_call(
                String::from("table"),
                String::from("hello"),
                osquery::ExtensionPluginRequest::new(),
            )
            .unwrap();

        assert_eq!(
            res.status.unwrap().message.unwrap(),
            "Unknown registry item: hello",
            "hello should not be found"
        );
    }

    #[test]
    fn socket_path_too_long() {
        let long_path = "a".repeat(MAX_SOCKET_PATH_CHARACTERS + 1);
        let result = ExtensionManagerServer::new("test", &long_path);
        match result {
            Err(e) => assert!(
                e.to_string()
                    .contains("exceeded the maximum socket path character length"),
                "should report socket path length error, got: {e}"
            ),
            Ok(_) => panic!("expected error for long socket path"),
        }
    }

    #[test]
    fn socket_path_at_limit() {
        // A path exactly at the limit should not fail with a length error.
        // It will fail trying to connect (no such socket), which is expected.
        let limit_path = "a".repeat(MAX_SOCKET_PATH_CHARACTERS);
        let result = ExtensionManagerServer::new("test", &limit_path);
        match result {
            Err(e) => assert!(
                !e.to_string()
                    .contains("exceeded the maximum socket path character length"),
                "should not be a path length error, got: {e}"
            ),
            Ok(_) => panic!("expected connection error for non-existent socket"),
        }
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn builder_custom_options() {
        let server = ExtensionManagerServer::builder("test_opts", test_socket())
            .version("1.0.0")
            .timeout(time::Duration::from_secs(2))
            .ping_interval(time::Duration::from_secs(10))
            .build()
            .unwrap();
        assert_eq!(server.version, Some("1.0.0".to_string()));
        assert_eq!(server.ping_interval, time::Duration::from_secs(10));
        assert!(
            server.client_ownership == ClientOwnership::Owned,
            "server-created client should be marked as Owned"
        );
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn register_plugins_batch() {
        let mut server = init_server();
        let plugins: Vec<Box<dyn OsqueryPlugin>> = vec![
            Box::new(mock::MockPlugin::new("plugin_a", RegistryName::Table)),
            Box::new(mock::MockPlugin::new("plugin_b", RegistryName::Logger)),
            Box::new(mock::MockPlugin::new("plugin_c", RegistryName::Config)),
        ];
        server.register_plugins(plugins).unwrap();

        let registry = server.registry.lock().unwrap();
        assert!(
            registry
                .get(&RegistryName::Table)
                .and_then(|r| r.get("plugin_a"))
                .is_some(),
            "plugin_a should be in table registry"
        );
        assert!(
            registry
                .get(&RegistryName::Logger)
                .and_then(|r| r.get("plugin_b"))
                .is_some(),
            "plugin_b should be in logger registry"
        );
        assert!(
            registry
                .get(&RegistryName::Config)
                .and_then(|r| r.get("plugin_c"))
                .is_some(),
            "plugin_c should be in config registry"
        );
    }

    #[test]
    fn shutdown_handle_sends_signal() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handle = ShutdownHandle { sender: tx };
        handle.shutdown();
        assert!(
            rx.recv().unwrap().is_none(),
            "shutdown handle should send None (clean shutdown)"
        );
    }

    #[test]
    fn shutdown_handle_is_clone() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handle = ShutdownHandle { sender: tx };
        let handle2 = handle.clone();
        drop(handle);
        handle2.shutdown();
        assert!(
            rx.recv().unwrap().is_none(),
            "cloned handle should send shutdown signal"
        );
    }

    #[test]
    fn shutdown_handle_multiple_calls_safe() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let handle = ShutdownHandle { sender: tx };
        handle.shutdown();
        // Second call should silently fail (channel already has a message)
        handle.shutdown();
        assert!(
            rx.recv().unwrap().is_none(),
            "first shutdown should be clean"
        );
    }

    #[test]
    fn shutdown_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ShutdownHandle>();
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn shutdown_handle_from_server() {
        let server = init_server();
        let handle = server.shutdown_handle();
        let handle2 = handle.clone();
        drop(handle2);
        drop(handle);
    }

    /// Build a server backed by the given mock client, listening on a unique
    /// per-test socket. Returns the server and its listen path (mock
    /// registration always assigns uuid 1).
    #[cfg(feature = "mock")]
    fn init_mock_server(
        test_name: &str,
        client: crate::mock::MockExtensionManager,
    ) -> (ExtensionManagerServer, std::path::PathBuf) {
        #[cfg(unix)]
        let socket = format!("/tmp/osquery_rs_sdk.manager.{test_name}.em");
        #[cfg(windows)]
        let socket = format!(r"\\.\pipe\osquery_rs_sdk.manager.{test_name}.em");
        let listen_path = std::path::PathBuf::from(format!("{socket}.1"));
        std::fs::remove_file(&socket).ok();
        std::fs::remove_file(&listen_path).ok();

        let server = ExtensionManagerServer::builder(test_name, socket)
            .client(Box::new(client))
            .ping_interval(std::time::Duration::from_millis(25))
            .build()
            .unwrap();
        (server, listen_path)
    }

    #[cfg(feature = "mock")]
    #[test]
    fn shutdown_invokes_plugin_shutdown_hooks() {
        use crate::plugin::LoggerPlugin;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (mut server, listen_path) = init_mock_server(
            "plugin_shutdown_hook",
            crate::mock::MockExtensionManager::new(),
        );

        let flushed = Arc::new(AtomicBool::new(false));
        let flushed_in_hook = Arc::clone(&flushed);
        let logger = LoggerPlugin::new("hook_logger", |_typ, _log| Ok(()))
            .with_shutdown(move || flushed_in_hook.store(true, Ordering::SeqCst));
        server.register_plugin(logger).unwrap();

        let handle = server.shutdown_handle();
        let run_thread = std::thread::spawn(move || server.run());
        wait_for_extension_server(&listen_path);

        handle.shutdown();
        run_thread.join().unwrap().unwrap();

        assert!(
            flushed.load(Ordering::SeqCst),
            "plugin shutdown hook should fire during server shutdown"
        );
    }

    /// A ping wedged inside a blocking RPC (holding the client mutex) must
    /// not prevent `run()` from completing shutdown.
    #[cfg(feature = "mock")]
    #[test]
    fn shutdown_completes_while_ping_is_wedged() {
        use std::time::Duration;

        let (ping_started_tx, ping_started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut mock = crate::mock::MockExtensionManager::new();
        mock.ping_fn = Some(Box::new(move || {
            ping_started_tx.send(()).ok();
            release_rx.recv().ok(); // Park, simulating a hung osquery socket.
            Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
        }));

        let (mut server, listen_path) = init_mock_server("wedged_ping", mock);
        let handle = server.shutdown_handle();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            done_tx.send(server.run()).ok();
        });
        wait_for_extension_server(&listen_path);

        ping_started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a ping should be in flight");
        handle.shutdown();

        let outcome = done_rx.recv_timeout(Duration::from_secs(5));
        // Unwedge regardless of outcome so the parked thread unwinds.
        release_tx.send(()).ok();

        outcome
            .expect("run() must complete while a ping is wedged")
            .expect("wedged-ping shutdown should still succeed");
    }

    #[cfg(feature = "mock")]
    #[test]
    fn ping_thread_stops_when_run_returns() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let pings = Arc::new(AtomicUsize::new(0));
        let pings_in_fn = Arc::clone(&pings);
        let mut mock = crate::mock::MockExtensionManager::new();
        mock.ping_fn = Some(Box::new(move || {
            pings_in_fn.fetch_add(1, Ordering::SeqCst);
            Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
        }));

        let (mut server, listen_path) = init_mock_server("ping_thread_stop", mock);
        let handle = server.shutdown_handle();
        let run_thread = std::thread::spawn(move || server.run());
        wait_for_extension_server(&listen_path);

        handle.shutdown();
        run_thread.join().unwrap().unwrap();

        let pings_at_shutdown = pings.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(
            pings.load(Ordering::SeqCst),
            pings_at_shutdown,
            "ping thread should stop when run() returns"
        );
    }
}
