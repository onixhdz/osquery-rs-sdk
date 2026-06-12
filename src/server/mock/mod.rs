use crate::osquery;

/// `MockExtensionServerHandler` impl the `ExtensionSyncHandler` interface to mock a server handler
pub struct MockExtensionServerHandler {}

impl osquery::ExtensionSyncHandler for MockExtensionServerHandler {
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::new(0, "OK".to_string(), None))
    }

    fn handle_call(
        &self,
        _registry: String,
        _item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        // Echo the request back so transport tests can verify round-trips.
        Ok(osquery::ExtensionResponse::new(
            osquery::ExtensionStatus::new(0, "OK".to_string(), None),
            vec![request],
        ))
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        Ok(())
    }
}
