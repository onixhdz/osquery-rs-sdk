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
use crate::{OsqueryPlugin, RegistryName, Result, osquery};
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
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        match req.get("action").map(String::as_str) {
            Some("genConfig") => match (self.generate)() {
                Ok(conf) => osquery::ExtensionResponse::new(
                    osquery::ExtensionStatus::new(0, String::from("OK"), None),
                    osquery::ExtensionPluginResponse::from([conf]),
                ),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("error getting config: {}", err);
                    osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(
                            1,
                            err.context("error getting config").to_string(),
                            None,
                        ),
                        None,
                    )
                }
            },
            Some("genPack") => {
                let Some(name) = req.get("name") else {
                    return osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(
                            1,
                            String::from("missing name in genPack request"),
                            None,
                        ),
                        None,
                    );
                };
                let Some(value) = req.get("value") else {
                    return osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(
                            1,
                            String::from("missing value in genPack request"),
                            None,
                        ),
                        None,
                    );
                };
                let Some(gen_pack) = self.gen_pack.as_mut() else {
                    return osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(
                            1,
                            String::from("genPack not supported"),
                            None,
                        ),
                        None,
                    );
                };
                match gen_pack(name, value) {
                    Ok(pack) => osquery::ExtensionResponse::new(
                        osquery::ExtensionStatus::new(0, String::from("OK"), None),
                        osquery::ExtensionPluginResponse::from([BTreeMap::from([(
                            name.clone(),
                            pack,
                        )])]),
                    ),
                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!("error generating pack: {}", err);
                        osquery::ExtensionResponse::new(
                            osquery::ExtensionStatus::new(
                                1,
                                err.context("error generating pack").to_string(),
                                None,
                            ),
                            None,
                        )
                    }
                }
            }
            Some(action) => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, format!("unknown action: {action}"), None),
                None,
            ),
            None => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(1, String::from("missing action"), None),
                None,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_plugin() {
        let mut called = false;
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);

        let mut plugin = ConfigPlugin::new("mock", || {
            called = true;
            Ok(BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )]))
        });

        assert_eq!(plugin.name(), "mock");
        assert_eq!(plugin.registry_name(), RegistryName::Config);

        let res = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("genConfig"),
        )]));

        assert!(called, "generate function never called");
        assert_eq!(res.status.unwrap(), status_ok);
        assert_eq!(
            res.response.unwrap(),
            osquery::ExtensionPluginResponse::from([BTreeMap::from([(
                "conf1".to_string(),
                "foobar".to_string(),
            )])])
        );
    }

    #[test]
    fn config_plugin_error() {
        let mut plugin = ConfigPlugin::new("mock", || Err("foobar".into()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("genConfig"),
        )]));
        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from(r"error getting config - foobar")
        );
    }

    #[test]
    fn config_plugin_gen_pack() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|name, value| Ok(format!(r#"{{"pack":"{name}","src":"{value}"}}"#)));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("genPack")),
            (String::from("name"), String::from("my_pack")),
            (
                String::from("value"),
                String::from("/etc/osquery/packs/my_pack.conf"),
            ),
        ]));

        assert_eq!(res.status.clone().unwrap().code.unwrap(), 0);
        assert_eq!(
            res.response.unwrap(),
            osquery::ExtensionPluginResponse::from([BTreeMap::from([(
                "my_pack".to_string(),
                r#"{"pack":"my_pack","src":"/etc/osquery/packs/my_pack.conf"}"#.to_string(),
            )])])
        );
    }

    #[test]
    fn config_plugin_gen_pack_not_supported() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("genPack")),
            (String::from("name"), String::from("my_pack")),
            (String::from("value"), String::from("target")),
        ]));

        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from("genPack not supported")
        );
    }

    #[test]
    fn config_plugin_gen_pack_missing_name() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Ok(String::new()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("genPack")),
            (String::from("value"), String::from("target")),
        ]));

        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from("missing name in genPack request")
        );
    }

    #[test]
    fn config_plugin_gen_pack_missing_value() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Ok(String::new()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("genPack")),
            (String::from("name"), String::from("my_pack")),
        ]));

        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from("missing value in genPack request")
        );
    }

    #[test]
    fn config_plugin_gen_pack_error() {
        let mut plugin = ConfigPlugin::new("mock", || Ok(BTreeMap::new()))
            .with_gen_pack(|_, _| Err("pack error".into()));

        let res = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("genPack")),
            (String::from("name"), String::from("my_pack")),
            (String::from("value"), String::from("target")),
        ]));

        assert_eq!(res.status.clone().unwrap().code.unwrap(), 1);
        assert_eq!(
            res.status.unwrap().message.unwrap(),
            String::from("error generating pack - pack error")
        );
    }
}
