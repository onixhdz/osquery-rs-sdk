//! Public mock implementations for testing osquery extensions.
//!
//! Enable with the `mock` feature flag:
//! ```toml
//! [dev-dependencies]
//! osquery-rs-sdk = { version = "0.1", features = ["mock"] }
//! ```
//!
//! # `MockExtensionManager`
//!
//! Implements [`ExtensionManager`] with injectable
//! function fields and invocation tracking. Unset functions return sensible defaults.
//!
//! ```rust,no_run
//! use osquery_rs_sdk::mock::MockExtensionManager;
//!
//! let mock = MockExtensionManager::new();
//! // Use as a server client via builder:
//! // ExtensionManagerServer::builder("ext", socket).client(Box::new(mock)).build()
//! ```

use crate::{client::ExtensionManager, osquery};
use std::sync::atomic::{AtomicUsize, Ordering};
use thrift::Result as TResult;

// ---------------------------------------------------------------------------
// Type aliases for mock function fields
// ---------------------------------------------------------------------------

type CloseFn = Box<dyn FnMut() + Send>;

type PingFn = Box<dyn FnMut() -> TResult<osquery::ExtensionStatus> + Send>;

type CallFn = Box<
    dyn FnMut(&str, &str, osquery::ExtensionPluginRequest) -> TResult<osquery::ExtensionResponse>
        + Send,
>;

type ShutdownMockFn = Box<dyn FnMut() -> TResult<()> + Send>;

type ExtensionsFn = Box<dyn FnMut() -> TResult<osquery::InternalExtensionList> + Send>;

type OptionsFn = Box<dyn FnMut() -> TResult<osquery::InternalOptionList> + Send>;

type RegisterExtensionFn = Box<
    dyn FnMut(
            osquery::InternalExtensionInfo,
            osquery::ExtensionRegistry,
        ) -> TResult<osquery::ExtensionStatus>
        + Send,
>;

type DeregisterExtensionFn =
    Box<dyn FnMut(osquery::ExtensionRouteUUID) -> TResult<osquery::ExtensionStatus> + Send>;

type QueryFn = Box<dyn FnMut(&str) -> TResult<osquery::ExtensionResponse> + Send>;

// ---------------------------------------------------------------------------
// MockExtensionManager
// ---------------------------------------------------------------------------

/// A mock implementation of [`ExtensionManager`] for testing.
///
/// Each trait method has a corresponding `*_fn` field that can be set to
/// override the default behavior, and a `*_call_count` counter that tracks
/// how many times the method was called.
///
/// By default, methods return success with reasonable values (status code 0,
/// empty responses). Set a `*_fn` field to inject custom behavior.
pub struct MockExtensionManager {
    /// Override for [`ExtensionManager::close`]. Default: no-op.
    pub close_fn: Option<CloseFn>,
    /// Number of times `close` was called.
    pub close_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::ping`]. Default: returns OK status.
    pub ping_fn: Option<PingFn>,
    /// Number of times `ping` was called.
    pub ping_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::call`]. Default: returns OK with empty response.
    pub call_fn: Option<CallFn>,
    /// Number of times `call` was called.
    pub call_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::shutdown`]. Default: returns Ok(()).
    pub shutdown_fn: Option<ShutdownMockFn>,
    /// Number of times `shutdown` was called.
    pub shutdown_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::extensions`]. Default: returns empty list.
    pub extensions_fn: Option<ExtensionsFn>,
    /// Number of times `extensions` was called.
    pub extensions_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::options`]. Default: returns empty list.
    pub options_fn: Option<OptionsFn>,
    /// Number of times `options` was called.
    pub options_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::register_extension`]. Default: returns OK status with UUID 1.
    pub register_extension_fn: Option<RegisterExtensionFn>,
    /// Number of times `register_extension` was called.
    pub register_extension_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::deregister_extension`]. Default: returns OK status.
    pub deregister_extension_fn: Option<DeregisterExtensionFn>,
    /// Number of times `deregister_extension` was called.
    pub deregister_extension_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::query`]. Default: returns OK with empty response.
    pub query_fn: Option<QueryFn>,
    /// Number of times `query` was called.
    pub query_call_count: AtomicUsize,

    /// Override for [`ExtensionManager::get_query_columns`]. Default: returns OK with empty response.
    pub get_query_columns_fn: Option<QueryFn>,
    /// Number of times `get_query_columns` was called.
    pub get_query_columns_call_count: AtomicUsize,
}

impl MockExtensionManager {
    /// Create a new mock with default (success) behavior for all methods.
    #[must_use]
    pub fn new() -> Self {
        Self {
            close_fn: None,
            close_call_count: AtomicUsize::new(0),
            ping_fn: None,
            ping_call_count: AtomicUsize::new(0),
            call_fn: None,
            call_call_count: AtomicUsize::new(0),
            shutdown_fn: None,
            shutdown_call_count: AtomicUsize::new(0),
            extensions_fn: None,
            extensions_call_count: AtomicUsize::new(0),
            options_fn: None,
            options_call_count: AtomicUsize::new(0),
            register_extension_fn: None,
            register_extension_call_count: AtomicUsize::new(0),
            deregister_extension_fn: None,
            deregister_extension_call_count: AtomicUsize::new(0),
            query_fn: None,
            query_call_count: AtomicUsize::new(0),
            get_query_columns_fn: None,
            get_query_columns_call_count: AtomicUsize::new(0),
        }
    }

    /// Return whether `close` was called at least once.
    #[must_use]
    pub fn close_invoked(&self) -> bool {
        self.close_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `ping` was called at least once.
    #[must_use]
    pub fn ping_invoked(&self) -> bool {
        self.ping_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `call` was called at least once.
    #[must_use]
    pub fn call_invoked(&self) -> bool {
        self.call_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `shutdown` was called at least once.
    #[must_use]
    pub fn shutdown_invoked(&self) -> bool {
        self.shutdown_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `extensions` was called at least once.
    #[must_use]
    pub fn extensions_invoked(&self) -> bool {
        self.extensions_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `options` was called at least once.
    #[must_use]
    pub fn options_invoked(&self) -> bool {
        self.options_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `register_extension` was called at least once.
    #[must_use]
    pub fn register_extension_invoked(&self) -> bool {
        self.register_extension_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `deregister_extension` was called at least once.
    #[must_use]
    pub fn deregister_extension_invoked(&self) -> bool {
        self.deregister_extension_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `query` was called at least once.
    #[must_use]
    pub fn query_invoked(&self) -> bool {
        self.query_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `get_query_columns` was called at least once.
    #[must_use]
    pub fn get_query_columns_invoked(&self) -> bool {
        self.get_query_columns_call_count.load(Ordering::Relaxed) > 0
    }
}

impl std::fmt::Debug for MockExtensionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockExtensionManager")
            .field("close_call_count", &self.close_call_count)
            .field("ping_call_count", &self.ping_call_count)
            .field("call_call_count", &self.call_call_count)
            .field("shutdown_call_count", &self.shutdown_call_count)
            .field("extensions_call_count", &self.extensions_call_count)
            .field("options_call_count", &self.options_call_count)
            .field(
                "register_extension_call_count",
                &self.register_extension_call_count,
            )
            .field(
                "deregister_extension_call_count",
                &self.deregister_extension_call_count,
            )
            .field("query_call_count", &self.query_call_count)
            .field(
                "get_query_columns_call_count",
                &self.get_query_columns_call_count,
            )
            .finish_non_exhaustive()
    }
}

impl Default for MockExtensionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a default OK [`osquery::ExtensionStatus`].
fn ok_status() -> osquery::ExtensionStatus {
    osquery::ExtensionStatus::new(0, "OK".to_string(), None)
}

/// Returns a default OK [`osquery::ExtensionResponse`] with empty response.
fn ok_response() -> osquery::ExtensionResponse {
    osquery::ExtensionResponse::new(ok_status(), None)
}

impl ExtensionManager for MockExtensionManager {
    fn close(&mut self) {
        self.close_call_count.fetch_add(1, Ordering::Relaxed);
        if let Some(f) = &mut self.close_fn {
            f();
        }
    }

    fn ping(&mut self) -> TResult<osquery::ExtensionStatus> {
        self.ping_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.ping_fn {
            Some(f) => f(),
            None => Ok(ok_status()),
        }
    }

    fn call(
        &mut self,
        registry: &str,
        item: &str,
        request: osquery::ExtensionPluginRequest,
    ) -> TResult<osquery::ExtensionResponse> {
        self.call_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.call_fn {
            Some(f) => f(registry, item, request),
            None => Ok(ok_response()),
        }
    }

    fn shutdown(&mut self) -> TResult<()> {
        self.shutdown_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.shutdown_fn {
            Some(f) => f(),
            None => Ok(()),
        }
    }

    fn extensions(&mut self) -> TResult<osquery::InternalExtensionList> {
        self.extensions_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.extensions_fn {
            Some(f) => f(),
            None => Ok(osquery::InternalExtensionList::new()),
        }
    }

    fn options(&mut self) -> TResult<osquery::InternalOptionList> {
        self.options_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.options_fn {
            Some(f) => f(),
            None => Ok(osquery::InternalOptionList::new()),
        }
    }

    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> TResult<osquery::ExtensionStatus> {
        self.register_extension_call_count
            .fetch_add(1, Ordering::Relaxed);
        match &mut self.register_extension_fn {
            Some(f) => f(info, registry),
            None => Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), Some(1))),
        }
    }

    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> TResult<osquery::ExtensionStatus> {
        self.deregister_extension_call_count
            .fetch_add(1, Ordering::Relaxed);
        match &mut self.deregister_extension_fn {
            Some(f) => f(uuid),
            None => Ok(ok_status()),
        }
    }

    fn query(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        self.query_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.query_fn {
            Some(f) => f(sql),
            None => Ok(ok_response()),
        }
    }

    fn get_query_columns(&mut self, sql: &str) -> TResult<osquery::ExtensionResponse> {
        self.get_query_columns_call_count
            .fetch_add(1, Ordering::Relaxed);
        match &mut self.get_query_columns_fn {
            Some(f) => f(sql),
            None => Ok(ok_response()),
        }
    }
}

// ---------------------------------------------------------------------------
// MockPlugin
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
use crate::{OsqueryPlugin, RegistryName};

/// A mock implementation of [`OsqueryPlugin`] for testing.
///
/// Each method has a corresponding `*_fn` field for overriding default behavior
/// and a `*_call_count` counter that tracks invocations.
/// By default, `call` returns an empty response with status code 0.
#[cfg(feature = "server")]
pub struct MockPlugin {
    name: String,
    registry_name: RegistryName,

    /// Override for [`OsqueryPlugin::call`]. Default: returns OK with empty response.
    pub call_fn: Option<
        Box<dyn FnMut(osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse + Send + Sync>,
    >,
    /// Number of times `call` was called.
    pub call_call_count: AtomicUsize,

    /// Override for [`OsqueryPlugin::routes`]. Default: returns empty response.
    pub routes_fn: Option<Box<dyn Fn() -> osquery::ExtensionPluginResponse + Send + Sync>>,
    /// Number of times `routes` was called.
    pub routes_call_count: AtomicUsize,

    /// Override for [`OsqueryPlugin::ping`]. Default: returns OK status.
    pub ping_fn: Option<Box<dyn Fn() -> osquery::ExtensionStatus + Send + Sync>>,
    /// Number of times `ping` was called.
    pub ping_call_count: AtomicUsize,

    /// Override for [`OsqueryPlugin::shutdown`]. Default: no-op.
    pub shutdown_fn: Option<Box<dyn Fn() + Send + Sync>>,
    /// Number of times `shutdown` was called.
    pub shutdown_call_count: AtomicUsize,
}

#[cfg(feature = "server")]
impl MockPlugin {
    /// Create a new mock plugin with the given name and registry.
    #[must_use]
    pub fn new(name: &str, registry_name: RegistryName) -> Self {
        Self {
            name: name.to_string(),
            registry_name,
            call_fn: None,
            call_call_count: AtomicUsize::new(0),
            routes_fn: None,
            routes_call_count: AtomicUsize::new(0),
            ping_fn: None,
            ping_call_count: AtomicUsize::new(0),
            shutdown_fn: None,
            shutdown_call_count: AtomicUsize::new(0),
        }
    }

    /// Return whether `call` was called at least once.
    #[must_use]
    pub fn call_invoked(&self) -> bool {
        self.call_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `routes` was called at least once.
    #[must_use]
    pub fn routes_invoked(&self) -> bool {
        self.routes_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `ping` was called at least once.
    #[must_use]
    pub fn ping_invoked(&self) -> bool {
        self.ping_call_count.load(Ordering::Relaxed) > 0
    }

    /// Return whether `shutdown` was called at least once.
    #[must_use]
    pub fn shutdown_invoked(&self) -> bool {
        self.shutdown_call_count.load(Ordering::Relaxed) > 0
    }
}

#[cfg(feature = "server")]
impl std::fmt::Debug for MockPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockPlugin")
            .field("name", &self.name)
            .field("registry_name", &self.registry_name)
            .field("call_call_count", &self.call_call_count)
            .field("routes_call_count", &self.routes_call_count)
            .field("ping_call_count", &self.ping_call_count)
            .field("shutdown_call_count", &self.shutdown_call_count)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "server")]
impl OsqueryPlugin for MockPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        self.registry_name
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        self.routes_call_count.fetch_add(1, Ordering::Relaxed);
        match &self.routes_fn {
            Some(f) => f(),
            None => osquery::ExtensionPluginResponse::new(),
        }
    }

    fn ping(&self) -> osquery::ExtensionStatus {
        self.ping_call_count.fetch_add(1, Ordering::Relaxed);
        match &self.ping_fn {
            Some(f) => f(),
            None => osquery::ExtensionStatus::new(0, "OK".to_string(), None),
        }
    }

    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        self.call_call_count.fetch_add(1, Ordering::Relaxed);
        match &mut self.call_fn {
            Some(f) => f(req),
            None => ok_response(),
        }
    }

    fn shutdown(&self) {
        self.shutdown_call_count.fetch_add(1, Ordering::Relaxed);
        if let Some(f) = &self.shutdown_fn {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_extension_manager_defaults() {
        let mut mock = MockExtensionManager::new();

        // All invoked flags start false
        assert!(!mock.ping_invoked());
        assert!(!mock.call_invoked());
        assert!(!mock.close_invoked());

        // Ping returns OK by default
        let status = mock.ping().unwrap();
        assert_eq!(status.code.unwrap(), 0);
        assert!(mock.ping_invoked());

        // Call returns OK by default
        let resp = mock
            .call("table", "test", osquery::ExtensionPluginRequest::new())
            .unwrap();
        assert_eq!(resp.status.unwrap().code.unwrap(), 0);
        assert!(mock.call_invoked());

        // Register returns OK with UUID 1
        let status = mock
            .register_extension(
                osquery::InternalExtensionInfo::new("test".to_string(), None, None, None),
                osquery::ExtensionRegistry::new(),
            )
            .unwrap();
        assert_eq!(status.code.unwrap(), 0);
        assert_eq!(status.uuid.unwrap(), 1);
        assert!(mock.register_extension_invoked());
    }

    #[test]
    fn mock_extension_manager_custom_fns() {
        let mut mock = MockExtensionManager::new();
        mock.ping_fn = Some(Box::new(|| {
            Ok(osquery::ExtensionStatus::new(
                1,
                "custom error".to_string(),
                None,
            ))
        }));

        let status = mock.ping().unwrap();
        assert_eq!(status.code.unwrap(), 1);
        assert_eq!(status.message.unwrap(), "custom error");
        assert!(mock.ping_invoked());
    }

    #[test]
    fn mock_extension_manager_query() {
        let mut mock = MockExtensionManager::new();
        mock.query_fn = Some(Box::new(|sql| {
            assert_eq!(sql, "SELECT 1");
            Ok(osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(0, "OK".to_string(), None),
                Some(vec![std::collections::BTreeMap::from([(
                    "1".to_string(),
                    "1".to_string(),
                )])]),
            ))
        }));

        let resp = mock.query("SELECT 1").unwrap();
        assert!(mock.query_invoked());
        assert_eq!(resp.response.unwrap().len(), 1);
    }

    #[test]
    fn mock_extension_manager_close_tracking() {
        let mut mock = MockExtensionManager::new();
        assert!(!mock.close_invoked());
        mock.close();
        assert!(mock.close_invoked());
    }

    #[cfg(feature = "server")]
    mod plugin_tests {
        use super::*;
        use crate::RegistryName;

        #[test]
        fn mock_plugin_defaults() {
            let mut plugin = MockPlugin::new("test_table", RegistryName::Table);

            assert_eq!(plugin.name(), "test_table");
            assert_eq!(plugin.registry_name(), RegistryName::Table);

            // Call returns OK by default
            let resp = plugin.call(osquery::ExtensionPluginRequest::new());
            assert_eq!(resp.status.unwrap().code.unwrap(), 0);
            assert!(plugin.call_invoked());
        }

        #[test]
        fn mock_plugin_custom_call() {
            let mut plugin = MockPlugin::new("test_table", RegistryName::Table);
            plugin.call_fn = Some(Box::new(|_req| {
                osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(42, "custom".to_string(), None),
                    None,
                )
            }));

            let resp = plugin.call(osquery::ExtensionPluginRequest::new());
            assert_eq!(resp.status.unwrap().code.unwrap(), 42);
            assert!(plugin.call_invoked());
        }
    }
}
