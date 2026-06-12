use crate::{Error, ExtensionRegistry, ExtensionUuid, PluginRequest, PluginResponse, Result};
use crate::{client::sealed, osquery};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};
use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol},
    transport::{TBufferedReadTransport, TBufferedWriteTransport},
};

#[cfg(unix)]
type TClient = std::os::unix::net::UnixStream;
#[cfg(windows)]
type TClient = super::named_pipe::NamedPipeClient;

/// Metadata for a registered extension, as reported by osquery.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionInfo {
    /// Identifier osquery assigned to the extension.
    pub uuid: ExtensionUuid,
    /// Extension name.
    pub name: String,
    /// Extension version.
    pub version: String,
    /// osquery SDK version the extension was built with.
    pub sdk_version: String,
    /// Minimum osquery SDK version the extension requires.
    pub min_sdk_version: String,
}

/// A bootstrap or configuration option reported by osquery.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionInfo {
    /// Current option value.
    pub value: String,
    /// Default option value.
    pub default_value: String,
    /// Option type label.
    pub option_type: String,
}

/// `ExtensionManager` represents an extension manager, which handles the
/// communication with the osquery core process.
///
/// This trait is sealed: it is implemented by [`ExtensionManagerClient`] and,
/// with the `mock` feature, by
/// [`MockExtensionManager`](crate::mock::MockExtensionManager). It cannot be
/// implemented outside this crate.
pub trait ExtensionManager: sealed::Sealed + Send {
    /// Close the transport connection. After close is called,
    /// other methods may return errors.
    fn close(&mut self);

    /// Check connectivity with the extension manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery reports a non-zero status, or a
    /// transport error if the connection fails.
    fn ping(&mut self) -> Result<()>;

    /// Call an extension (or core) registry plugin and return its response
    /// rows.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery reports a non-zero status, or a
    /// transport error if the connection fails.
    fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: PluginRequest,
    ) -> Result<PluginResponse>;

    /// Request the list of active registered extensions.
    ///
    /// # Errors
    ///
    /// Returns a transport error if the connection fails.
    fn extensions(&mut self) -> Result<Vec<ExtensionInfo>>;

    /// Request the list of bootstrap or configuration options.
    ///
    /// # Errors
    ///
    /// Returns a transport error if the connection fails.
    fn options(&mut self) -> Result<BTreeMap<String, OptionInfo>>;

    /// Register the extension plugins with the osquery process and return
    /// the assigned extension uuid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery rejects the registration, or a
    /// transport error if the connection fails.
    fn register_extension(
        &mut self,
        name: &str,
        version: Option<&str>,
        registry: ExtensionRegistry,
    ) -> Result<ExtensionUuid>;

    /// De-register the extension plugins from the osquery process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery reports a non-zero status, or a
    /// transport error if the connection fails.
    fn deregister_extension(&mut self, uuid: ExtensionUuid) -> Result<()>;

    /// Execute a query and return the result rows.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the query fails (bad SQL, unknown table,
    /// missing required constraint, ...), or a transport error if the
    /// connection fails.
    fn query(&mut self, sql: &str) -> Result<PluginResponse>;

    /// Request the columns returned by the parsed query. Each row maps a
    /// column name to its type string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the query cannot be parsed, or a
    /// transport error if the connection fails.
    fn get_query_columns(&mut self, sql: &str) -> Result<PluginResponse>;
}

/// Fold a wire status into `Result`, returning the optional uuid carried by
/// registration replies. A missing status or code is a protocol anomaly and
/// reported as an error rather than trusted.
fn status_ok(status: Option<osquery::ExtensionStatus>) -> Result<Option<i64>> {
    let Some(status) = status else {
        return Err(Error::Other("response missing status".to_string()));
    };
    let code = status.code.unwrap_or(-1);
    if code == 0 {
        Ok(status.uuid)
    } else {
        Err(Error::Status {
            code,
            message: status.message.unwrap_or_default(),
        })
    }
}

/// Fold a wire response into its rows, surfacing non-zero status as
/// [`Error::Status`].
fn response_rows(response: osquery::ExtensionResponse) -> Result<PluginResponse> {
    status_ok(response.status)?;
    Ok(response.response.unwrap_or_default())
}

/// `ExtensionManagerClient` is a client for the osquery extensions API.
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

impl ExtensionManagerClient {
    /// Connect to osquery over the default socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the default `osqueryd` socket cannot be connected to.
    pub fn connect() -> Result<Self> {
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
    pub fn connect_with_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let stream = TClient::connect(&path).map_err(|e| {
            Error::from(e).context(&format!("connecting to {}", path.as_ref().display()))
        })?;
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
    ) -> Result<Self> {
        wait_for_socket(path.as_ref(), socket_open_timeout)
            .map_err(|e| Error::from(e).context("waiting for socket"))?;
        Self::connect_with_path(path)
    }

    /// Build a client from an already-connected stream.
    fn from_stream(stream: TClient) -> Result<Self> {
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

    /// Check connectivity with the extension manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery reports a non-zero status, or a
    /// transport error if the connection fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn ping(&mut self) -> Result<()> {
        status_ok(Some(self.client.ping()?)).map(|_| ())
    }

    /// Call an extension (or core) registry plugin and return its response
    /// rows.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if osquery reports a non-zero status, or a
    /// transport error if the connection fails.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, request), fields(registry = %registry, item = %item))
    )]
    pub fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: PluginRequest,
    ) -> Result<PluginResponse> {
        response_rows(
            self.client
                .call(registry.to_string(), item.to_string(), request)?,
        )
    }

    /// Request the list of active registered extensions.
    ///
    /// # Errors
    ///
    /// Returns a transport error if the connection fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn extensions(&mut self) -> Result<Vec<ExtensionInfo>> {
        Ok(self
            .client
            .extensions()?
            .into_iter()
            .map(|(uuid, info)| ExtensionInfo {
                uuid,
                name: info.name.unwrap_or_default(),
                version: info.version.unwrap_or_default(),
                sdk_version: info.sdk_version.unwrap_or_default(),
                min_sdk_version: info.min_sdk_version.unwrap_or_default(),
            })
            .collect())
    }

    /// Request the list of bootstrap or configuration options.
    ///
    /// # Errors
    ///
    /// Returns a transport error if the connection fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn options(&mut self) -> Result<BTreeMap<String, OptionInfo>> {
        Ok(self
            .client
            .options()?
            .into_iter()
            .map(|(name, info)| {
                (
                    name,
                    OptionInfo {
                        value: info.value.unwrap_or_default(),
                        default_value: info.default_value.unwrap_or_default(),
                        option_type: info.type_.unwrap_or_default(),
                    },
                )
            })
            .collect())
    }

    /// Execute a query and return the result rows.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the query fails, or a transport error if
    /// the connection fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn query(&mut self, sql: &str) -> Result<PluginResponse> {
        response_rows(self.client.query(sql.to_string())?)
    }

    /// Request the columns returned by the parsed query. Each row maps a
    /// column name to its type string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the query cannot be parsed, or a
    /// transport error if the connection fails.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn get_query_columns(&mut self, sql: &str) -> Result<PluginResponse> {
        response_rows(self.client.get_query_columns(sql.to_string())?)
    }

    /// Execute a query and return exactly one row.
    ///
    /// # Errors
    ///
    /// Returns an error if [`query`](Self::query) fails or if the result
    /// does not contain exactly one row.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self)))]
    pub fn query_row(&mut self, sql: &str) -> Result<BTreeMap<String, String>> {
        let rows = self.query(sql)?;
        if rows.len() != 1 {
            return Err(Error::Other(format!("expected 1 row, got {}", rows.len())));
        }
        rows.into_iter()
            .next()
            .ok_or_else(|| Error::Other("expected 1 row but iterator was empty".to_string()))
    }

    fn register_extension_impl(
        &mut self,
        name: &str,
        version: Option<&str>,
        registry: ExtensionRegistry,
    ) -> Result<ExtensionUuid> {
        let status = self.client.register_extension(
            osquery::InternalExtensionInfo::new(
                name.to_string(),
                version.map(str::to_string),
                None,
                None,
            ),
            registry,
        )?;
        status_ok(Some(status))?
            .ok_or_else(|| Error::Other("registration returned no uuid".to_string()))
    }

    fn deregister_extension_impl(&mut self, uuid: ExtensionUuid) -> Result<()> {
        status_ok(Some(self.client.deregister_extension(uuid)?)).map(|_| ())
    }
}

impl Drop for ExtensionManagerClient {
    fn drop(&mut self) {
        self.close();
    }
}

impl sealed::Sealed for ExtensionManagerClient {}

impl ExtensionManager for ExtensionManagerClient {
    fn close(&mut self) {
        ExtensionManagerClient::close(self);
    }

    fn ping(&mut self) -> Result<()> {
        ExtensionManagerClient::ping(self)
    }

    fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: PluginRequest,
    ) -> Result<PluginResponse> {
        ExtensionManagerClient::call(self, registry, item, request)
    }

    fn extensions(&mut self) -> Result<Vec<ExtensionInfo>> {
        ExtensionManagerClient::extensions(self)
    }

    fn options(&mut self) -> Result<BTreeMap<String, OptionInfo>> {
        ExtensionManagerClient::options(self)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip(self, registry)))]
    fn register_extension(
        &mut self,
        name: &str,
        version: Option<&str>,
        registry: ExtensionRegistry,
    ) -> Result<ExtensionUuid> {
        self.register_extension_impl(name, version, registry)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), fields(uuid = uuid))
    )]
    fn deregister_extension(&mut self, uuid: ExtensionUuid) -> Result<()> {
        self.deregister_extension_impl(uuid)
    }

    fn query(&mut self, sql: &str) -> Result<PluginResponse> {
        ExtensionManagerClient::query(self, sql)
    }

    fn get_query_columns(&mut self, sql: &str) -> Result<PluginResponse> {
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
        client.query("SELECT * FROM users").unwrap();
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_row() {
        let mut client = ExtensionManagerClient::connect_with_path(test_socket()).unwrap();
        client.query_row("SELECT * FROM users limit 1").unwrap();
    }

    #[test]
    #[ignore = "requires a running osqueryd extension socket"]
    #[serial]
    fn query_error_is_status() {
        let mut client = ExtensionManagerClient::connect_with_path(test_socket()).unwrap();
        let err = client
            .query("SELECT * FROM nonexistent_table_xyz")
            .unwrap_err();
        assert!(
            matches!(err, Error::Status { code, .. } if code != 0),
            "bad SQL should surface as Error::Status: {err}"
        );
    }

    #[test]
    fn status_ok_folds_codes() {
        assert!(status_ok(None).is_err(), "missing status is an error");
        let ok = osquery::ExtensionStatus::new(0, "OK".to_string(), Some(7));
        assert_eq!(status_ok(Some(ok)).unwrap(), Some(7));
        let fail = osquery::ExtensionStatus::new(1, "nope".to_string(), None);
        match status_ok(Some(fail)).unwrap_err() {
            Error::Status { code, message } => {
                assert_eq!(code, 1);
                assert_eq!(message, "nope");
            }
            other => panic!("expected Error::Status, got {other}"),
        }
        let missing_code = osquery::ExtensionStatus::new(None, "odd".to_string(), None);
        assert!(
            matches!(
                status_ok(Some(missing_code)),
                Err(Error::Status { code: -1, .. })
            ),
            "missing code must not be trusted as success"
        );
    }

    #[test]
    fn response_rows_folds_status() {
        let ok = osquery::ExtensionStatus::new(0, "OK".to_string(), None);
        let rows = vec![BTreeMap::from([("a".to_string(), "1".to_string())])];
        let resp = osquery::ExtensionResponse::new(ok, rows.clone());
        assert_eq!(response_rows(resp).unwrap(), rows);

        let fail = osquery::ExtensionStatus::new(2, "boom".to_string(), None);
        let resp = osquery::ExtensionResponse::new(fail, rows);
        assert!(matches!(
            response_rows(resp),
            Err(Error::Status { code: 2, .. })
        ));
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
