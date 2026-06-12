use crate::{PluginRequest, PluginResponse, Result};
use std::fmt;

mod manager;
mod threaded;
pub use manager::{ExtensionManagerServer, ExtensionManagerServerBuilder, ShutdownHandle};

/// Supported plugin registry types.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RegistryName {
    Table,
    Logger,
    Config,
    Distributed,
}

impl fmt::Display for RegistryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryName::Table => write!(f, "table"),
            RegistryName::Logger => write!(f, "logger"),
            RegistryName::Config => write!(f, "config"),
            RegistryName::Distributed => write!(f, "distributed"),
        }
    }
}

impl std::str::FromStr for RegistryName {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "table" => Ok(RegistryName::Table),
            "logger" => Ok(RegistryName::Logger),
            "config" => Ok(RegistryName::Config),
            "distributed" => Ok(RegistryName::Distributed),
            other => Err(format!("Unknown registry: {other}")),
        }
    }
}

/// An osquery extension plugin.
///
/// Implementations handle requests from osquery using SDK-owned types. The
/// dispatch layer converts results to the osquery wire format: `Ok(rows)`
/// becomes a success response, [`Error::Status`](crate::Error::Status)
/// preserves its code and message, and any other error becomes status 1
/// with the error's message.
pub trait OsqueryPlugin: Send + Sync {
    /// Return the plugin name (e.g. the table name it implements).
    fn name(&self) -> &str;

    /// Return the registry this plugin belongs to.
    fn registry_name(&self) -> RegistryName;

    /// Return the routes (column definitions, etc.) exposed by the plugin.
    fn routes(&self) -> PluginResponse {
        PluginResponse::new()
    }

    /// Health check. Succeeds by default.
    ///
    /// Advisory: osquery pings the extension as a whole, and the extension
    /// answers without consulting individual plugins.
    ///
    /// # Errors
    ///
    /// Implementations may report an unhealthy plugin as an error.
    fn ping(&self) -> Result<()> {
        Ok(())
    }

    /// Handle an incoming request from osquery and return response rows.
    ///
    /// # Errors
    ///
    /// Error conditions are implementor-defined; use
    /// [`Error::Status`](crate::Error::Status) to control the status code
    /// reported to osquery.
    fn call(&mut self, req: PluginRequest) -> Result<PluginResponse>;

    /// Called when the plugin is being shut down.
    fn shutdown(&self) {}
}

impl std::fmt::Debug for Box<dyn OsqueryPlugin> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Box::OsqueryPlugin")
            .field(&self.name())
            .field(&self.registry_name().to_string())
            .finish()
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_name() {
        assert_eq!(RegistryName::Table.to_string(), String::from("table"));
        assert_eq!(RegistryName::Logger.to_string(), String::from("logger"));
        assert_eq!(RegistryName::Config.to_string(), String::from("config"));
        assert_eq!(
            RegistryName::Distributed.to_string(),
            String::from("distributed")
        );
    }
}
