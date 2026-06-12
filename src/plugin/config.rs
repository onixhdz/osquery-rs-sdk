//! Create an osquery configuration plugin.
//!
//! A config plugin provides osquery with its runtime configuration. The main
//! entry point is the `generate` closure passed to [`ConfigPlugin::new`], which
//! returns a map of source names to JSON config strings.
//!
//! Optionally, a config plugin can also generate **query packs** on demand via
//! [`ConfigPlugin::with_gen_pack`]. osquery calls this when the main config
//! references a pack that should be resolved by the extension. The callback
//! receives the pack name and an opaque value string, and returns the pack
//! configuration JSON.
//!
//! See <https://osquery.readthedocs.io/en/latest/development/config-plugins/> for more.
use crate::{Error, OsqueryPlugin, PluginRequest, PluginResponse, RegistryName, Result};
use std::collections::BTreeMap;

/// Source name → config JSON map.
type Config = BTreeMap<String, String>;

/// Callback for the `genPack` action. Receives the pack name and value,
/// and returns the pack configuration JSON as a string.
type GenPackFn = Box<dyn FnMut(&str, &str) -> Result<String> + Send + Sync>;

/// Osquery configuration plugin that implements the `OsqueryPlugin` interface.
///
/// * `GenFunc`: returns a map of source names to JSON config strings.
///
/// Use [`with_gen_pack`](Self::with_gen_pack) to add optional pack generation
/// support for the `genPack` action.
pub struct ConfigPlugin<GenFunc: FnMut() -> Result<Config>> {
    name: String,
    generate: GenFunc,
    gen_pack: Option<GenPackFn>,
}

impl<GenFunc: FnMut() -> Result<Config>> std::fmt::Debug for ConfigPlugin<GenFunc> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigPlugin")
            .field("name", &self.name)
            .field("gen_pack", &self.gen_pack.is_some())
            .finish_non_exhaustive()
    }
}

impl<GenFunc: FnMut() -> Result<Config>> ConfigPlugin<GenFunc> {
    /// Create a new config plugin.
    ///
    /// `generate` returns a map of source names to config JSON strings.
    pub fn new(name: &str, generate: GenFunc) -> Self {
        Self {
            name: name.to_string(),
            generate,
            gen_pack: None,
        }
    }

    /// Add pack generation support to this config plugin.
    ///
    /// The callback receives the pack `name` and `value` from osquery and
    /// should return the pack configuration JSON as a string. osquery calls
    /// this when the main config references a pack that should be resolved
    /// by this extension (e.g. packs stored in a remote source, fetched
    /// lazily by name).
    ///
    /// Without this, any `genPack` requests from osquery will return
    /// an "unknown action" error.
    ///
    /// # Example
    ///
    /// ```
    /// # use osquery_rs_sdk::{ConfigPlugin, Result};
    /// # use std::collections::BTreeMap;
    /// let plugin = ConfigPlugin::new("my_config", || Ok(BTreeMap::new()))
    ///     .with_gen_pack(|name, _value| {
    ///         Ok(format!(r#"{{"queries":{{"q1":{{"query":"SELECT 1;","interval":60}}}}}}"#))
    ///     });
    /// ```
    #[must_use]
    pub fn with_gen_pack(
        mut self,
        gen_pack: impl FnMut(&str, &str) -> Result<String> + Send + Sync + 'static,
    ) -> Self {
        self.gen_pack = Some(Box::new(gen_pack));
        self
    }
}

impl<GenFunc: FnMut() -> Result<Config> + Send + Sync> OsqueryPlugin for ConfigPlugin<GenFunc> {
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        RegistryName::Config
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.name))
    )]
    fn call(&mut self, req: PluginRequest) -> Result<PluginResponse> {
        match req.get("action").map(String::as_str) {
            Some("genConfig") => match (self.generate)() {
                Ok(conf) => Ok(PluginResponse::from([conf])),
                // Pass Status through so implementors control the wire status code.
                Err(err @ Error::Status { .. }) => Err(err),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("error getting config: {}", err);
                    Err(err.context("error getting config"))
                }
            },
            Some("genPack") => {
                let Some(name) = req.get("name") else {
                    return Err(Error::Other("missing name in genPack request".to_string()));
                };
                let Some(value) = req.get("value") else {
                    return Err(Error::Other("missing value in genPack request".to_string()));
                };
                let Some(gen_pack) = self.gen_pack.as_mut() else {
                    return Err(Error::Other("genPack not supported".to_string()));
                };
                match gen_pack(name, value) {
                    Ok(pack) => Ok(PluginResponse::from([BTreeMap::from([(
                        name.clone(),
                        pack,
                    )])])),
                    Err(err @ Error::Status { .. }) => Err(err),
                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!("error generating pack: {}", err);
                        Err(err.context("error generating pack"))
                    }
                }
            }
            Some(action) => Err(Error::Other(format!("unknown action: {action}"))),
            None => Err(Error::Other("missing action".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_plugin() {
        let mut called = false;

        let mut plugin = ConfigPlugin::new("mock", || {
            called = true;
            Ok(BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )]))
        });

        assert_eq!(plugin.name(), "mock");
        assert_eq!(plugin.registry_name(), RegistryName::Config);

        let rows = plugin
            .call(PluginRequest::from([(
                String::from("action"),
                String::from("genConfig"),
            )]))
            .unwrap();

        assert!(called, "generate function never called");
        assert_eq!(
            rows,
            PluginResponse::from([BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )])])
        );
    }

    #[test]
    fn config_plugin_error() {
        let mut plugin = ConfigPlugin::new("mock", || Err("foobar".into()));

        let err = plugin
            .call(PluginRequest::from([(
                String::from("action"),
                String::from("genConfig"),
            )]))
            .unwrap_err();
        assert_eq!(err.to_string(), "error getting config - foobar");
    }

    #[test]
    fn config_status_error_passes_through() {
        let mut plugin = ConfigPlugin::new("mock", || {
            Err(Error::Status {
                code: 7,
                message: "custom code".to_string(),
            })
        });
        let err = plugin
            .call(PluginRequest::from([(
                String::from("action"),
                String::from("genConfig"),
            )]))
            .unwrap_err();
        assert!(
            matches!(err, Error::Status { code: 7, .. }),
            "Status errors must keep their code: {err}"
        );
    }

    #[test]
    fn config_plugin_gen_pack() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|name, value| Ok(format!(r#"{{"pack":"{name}","src":"{value}"}}"#)));

        let rows = plugin
            .call(PluginRequest::from([
                (String::from("action"), String::from("genPack")),
                (String::from("name"), String::from("my_pack")),
                (
                    String::from("value"),
                    String::from("/etc/osquery/packs/my_pack.conf"),
                ),
            ]))
            .unwrap();

        assert_eq!(
            rows,
            PluginResponse::from([BTreeMap::from([(
                "my_pack".to_string(),
                r#"{"pack":"my_pack","src":"/etc/osquery/packs/my_pack.conf"}"#.to_string(),
            )])])
        );
    }

    #[test]
    fn config_plugin_gen_pack_not_supported() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()));

        let err = plugin
            .call(PluginRequest::from([
                (String::from("action"), String::from("genPack")),
                (String::from("name"), String::from("my_pack")),
                (String::from("value"), String::from("target")),
            ]))
            .unwrap_err();
        assert_eq!(err.to_string(), "genPack not supported");
    }

    #[test]
    fn config_plugin_gen_pack_missing_name() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Ok(String::new()));

        let err = plugin
            .call(PluginRequest::from([
                (String::from("action"), String::from("genPack")),
                (String::from("value"), String::from("target")),
            ]))
            .unwrap_err();
        assert_eq!(err.to_string(), "missing name in genPack request");
    }

    #[test]
    fn config_plugin_gen_pack_missing_value() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Ok(String::new()));

        let err = plugin
            .call(PluginRequest::from([
                (String::from("action"), String::from("genPack")),
                (String::from("name"), String::from("my_pack")),
            ]))
            .unwrap_err();
        assert_eq!(err.to_string(), "missing value in genPack request");
    }

    #[test]
    fn config_plugin_gen_pack_error() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Err("pack error".into()));

        let err = plugin
            .call(PluginRequest::from([
                (String::from("action"), String::from("genPack")),
                (String::from("name"), String::from("my_pack")),
                (String::from("value"), String::from("target")),
            ]))
            .unwrap_err();
        assert_eq!(err.to_string(), "error generating pack - pack error");
    }
}
