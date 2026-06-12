use crate::{
    osquery,
    server::{OsqueryPlugin, RegistryName},
};

pub const STATUS_CODE: i32 = 9999;

pub struct MockPlugin {
    name: String,
    rname: RegistryName,
}

impl MockPlugin {
    pub fn new(name: &str, rname: RegistryName) -> Self {
        Self {
            name: name.to_string(),
            rname,
        }
    }
}

impl OsqueryPlugin for MockPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        self.rname
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        osquery::ExtensionPluginResponse::new()
    }

    fn call(&mut self, _req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        osquery::ExtensionResponse::new(
            osquery::ExtensionStatus::new(STATUS_CODE, None, None),
            None,
        )
    }
}

/// `MockExtensionServerHandler` impl the `ExtensionSyncHandler` interface to mock a server handler
#[allow(dead_code)]
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
