use crate::osquery;
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};
use thrift::{
    Result as TResult,
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol, TInputProtocol, TOutputProtocol},
    transport::{TBufferedReadTransport, TBufferedWriteTransport},
};

#[cfg(unix)]
type TClient = std::os::unix::net::UnixStream;
#[cfg(windows)]
type TClient = super::named_pipe::NamedPipeClient;

/// `ExtensionManager` represents an extension manager, which handles the
/// communication with the osquery core process.
pub trait ExtensionManager: Send {
    /// Close the transport connection. After close is called,
    /// other methods may return errors.
    fn close(&mut self);
    /// Request metadata from the extension manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn ping(&mut self) -> TResult<osquery::ExtensionStatus>;
    /// Request a call to an extension (or core) registry plugin.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse>;
    /// Shut down the remote endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn shutdown(&mut self) -> TResult<()>;
    /// Request the list of active registered extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList>;
    /// Request the list of bootstrap or configuration options.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn options(&mut self) -> TResult<osquery::InternalOptionList>;
    /// Register the extension plugins with the osquery process.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus>;
    /// De-register the extension plugins with the osquery process.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus>;
    /// Execute a query and return the extension response.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn query(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse>;
    /// Request the columns returned by the parsed query.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying transport or serialization fails.
    fn get_query_columns(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse>;
}

/// `ExtensionManagerClient` is a wrapper for the osquery Thrift extensions API.
pub struct ExtensionManagerClient {
    client: Box<dyn osquery::TExtensionManagerSyncClient + Send>,
    stream: Option<TClient>,
}

impl std::fmt::Debug for ExtensionManagerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionManagerClient")
            .field("connected", &self.stream.is_some())
            .finish_non_exhaustive()
    }
}

/// Polls for the socket file to exist, checking every 200ms until the
/// timeout is reached.
fn wait_for_socket(path: &Path, timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "timed out after {:?} waiting for socket at {}",
                    timeout,
                    path.display()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `ExtensionManagerClient` is a wrapper for the osquery Thrift extensions API.
impl ExtensionManagerClient {
    /// Connect to osquery over the default socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the default `osqueryd` socket cannot be connected to.
    pub fn connect() -> TResult<Self> {
        #[cfg(unix)]
        return Self::connect_with_path("/var/osquery/osquery.em");
        #[cfg(windows)]
        return Self::connect_with_path(r"\\.\pipe\osquery.em");
    }

    /// Connect to osquery over the provided socket path.
    /// The connection is attempted immediately without polling for the socket to exist.
    ///
    /// # Errors
    ///
    /// Returns an error if connecting to the socket at `path` fails.
    pub fn connect_with_path<P: AsRef<Path>>(path: P) -> TResult<Self> {
        let stream = TClient::connect(&path)
            .map_err(|e| format!("connecting to {}: {}", path.as_ref().display(), e))?;
        Self::from_stream(stream)
    }

    /// Connect to osquery over the provided socket path,
    /// polling for the socket to exist up to `socket_open_timeout`.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket does not appear within `socket_open_timeout`
    /// or if connecting to it fails.
    pub fn connect_with_timeout<P: AsRef<Path>>(
        path: P,
        socket_open_timeout: Duration,
    ) -> TResult<Self> {
        wait_for_socket(path.as_ref(), socket_open_timeout)
            .map_err(|e| format!("waiting for socket: {e}"))?;

        let stream = TClient::connect(&path)
            .map_err(|e| format!("connecting to {}: {}", path.as_ref().display(), e))?;
        Self::from_stream(stream)
    }

    /// Build a client from an already-connected stream.
    fn from_stream(stream: TClient) -> TResult<Self> {
        let transport_in = TBufferedReadTransport::new(stream.try_clone()?);
        let transport_out = TBufferedWriteTransport::new(stream.try_clone()?);
        let protocol_in = Box::new(TBinaryInputProtocol::new(transport_in, false));
        let protocol_out = Box::new(TBinaryOutputProtocol::new(transport_out, true));

        Ok(Self {
            client: Box::new(osquery::ExtensionManagerSyncClient::new(
                protocol_in,
                protocol_out,
            )),
            stream: Some(stream),
        })
    }

    /// Create a new client communicating to osquery over the provided transports.
    #[must_use]
    pub fn from_protocols(
        input_protocol: Box<dyn TInputProtocol + Send>,
        output_protocol: Box<dyn TOutputProtocol + Send>,
    ) -> Self {
        Self {
            client: Box::new(osquery::ExtensionManagerSyncClient::new(
                input_protocol,
                output_protocol,
            )),
            stream: None,
        }
    }

    /// Close the transport connection. After close is called,
    /// other methods may return errors.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            #[cfg(unix)]
            let _ = stream.shutdown(std::net::Shutdown::Both);
            // Marks the connection closed for the transports' cloned handles.
            #[cfg(windows)]
            stream.close();
        }
    }

    /// Request metadata from the extension manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        self.client.ping()
    }

    /// Call an extension (or core) registry plugin.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, request), fields(registry = %registry, item = %item))
    )]
    pub fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        self.client
            .call(registry.to_string(), item.to_string(), request)
    }

    /// Call the Thrift shutdown RPC on the remote end.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn shutdown(&mut self) -> TResult<()> {
        self.client.shutdown()
    }

    /// Request the list of active registered extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        self.client.extensions()
    }

    /// Request the list of bootstrap or configuration options.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        self.client.options()
    }

    /// Register the extension plugins with the osquery process.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, info, registry)))]
    pub fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        self.client.register_extension(info, registry)
    }

    /// De-register the extension plugins with the osquery process.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), fields(uuid = uuid))
    )]
    pub fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        self.client.deregister_extension(uuid)
    }

    /// Execute a query and return the extension response.
    /// Consider using the `query_row` or `query_rows` helpers for a more friendly interface.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn query(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        self.client.query(sql.to_string())
    }

    /// Request the columns returned by the parsed query.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn get_query_columns(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        self.client.get_query_columns(sql.to_string())
    }

    /// Execute a query and return the results as a `Vec` of rows.
    /// Handles checking both transport-level errors and osquery internal errors
    /// by returning a Thrift error type.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying Thrift transport fails, if the
    /// query returns a nil status, or if osquery reports a non-zero status code.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn query_rows(&mut self, sql: &str) -> TResult<Vec<BTreeMap<String, String>>> {
        let res = self.client.query(String::from(sql))?;

        let status = res.status.ok_or("query returned nil status")?;

        match status.code {
            None => Err("query returned nil status".into()),
            Some(0) => Ok(res.response.unwrap_or_default()),
            _ => Err(format!(
                "query returned TError: {}",
                status.message.unwrap_or_default()
            )
            .into()),
        }
    }

    /// Execute a query and return exactly one row.
    /// Returns an error if the query does not produce exactly one row.
    ///
    /// # Errors
    ///
    /// Returns an error if `query_rows` fails or if the result does not
    /// contain exactly one row.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn query_row(&mut self, sql: &str) -> TResult<BTreeMap<String, String>> {
        let res = self.query_rows(sql)?;
        match res.len() {
            1 => res
                .into_iter()
                .next()
                .ok_or_else(|| "expected 1 row but iterator was empty".into()),
            _ => Err(format!("expected 1 row, got {}", res.len()).into()),
        }
    }
}

impl Drop for ExtensionManagerClient {
    fn drop(&mut self) {
        self.close();
    }
}

impl ExtensionManager for ExtensionManagerClient {
    fn close(&mut self) {
        ExtensionManagerClient::close(self);
    }

    fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        ExtensionManagerClient::ping(self)
    }

    fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        ExtensionManagerClient::call(self, registry, item, request)
    }

    fn shutdown(&mut self) -> TResult<()> {
        ExtensionManagerClient::shutdown(self)
    }

    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        ExtensionManagerClient::extensions(self)
    }

    fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        ExtensionManagerClient::options(self)
    }

    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        ExtensionManagerClient::register_extension(self, info, registry)
    }

    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        ExtensionManagerClient::deregister_extension(self, uuid)
    }

    fn query(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        ExtensionManagerClient::query(self, sql)
    }

    fn get_query_columns(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        ExtensionManagerClient::get_query_columns(self, sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_rows() {
        let mut client = ExtensionManagerClient::connect_with_path(test_socket()).unwrap();
        client.query_rows("SELECT * FROM users").unwrap();
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_row() {
        let mut client = ExtensionManagerClient::connect_with_path(test_socket()).unwrap();
        client.query_row("SELECT * FROM users limit 1").unwrap();
    }

    #[test]
    fn wait_for_socket_timeout() {
        let path = std::path::Path::new("/tmp/nonexistent_osquery_test_socket.em");
        let result = wait_for_socket(path, Duration::from_millis(300));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("timed out"),
            "error should mention timeout: {err}"
        );
    }

    #[test]
    fn wait_for_socket_exists() {
        // Use a path that exists on every platform to verify early return.
        let path = std::env::temp_dir();
        let result = wait_for_socket(&path, Duration::from_millis(100));
        assert!(result.is_ok(), "should succeed for existing path");
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn connect_with_timeout_connects() {
        let client =
            ExtensionManagerClient::connect_with_timeout(test_socket(), Duration::from_secs(5));
        assert!(client.is_ok(), "should connect to running osqueryd");
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn close_then_ping_errors() {
        let mut client = ExtensionManagerClient::connect_with_path(test_socket()).unwrap();
        client.ping().unwrap(); // should succeed
        client.close();
        // After close, ping should fail (transport is closed)
        assert!(client.ping().is_err(), "ping should fail after close");
    }
}
