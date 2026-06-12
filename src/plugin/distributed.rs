//! Create an osquery distributed plugin.
//!
//! See <https://osquery.readthedocs.io/en/latest/development/distributed-plugins/> for more.
use crate::{OsqueryPlugin, RegistryName, Result, osquery};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use std::{collections::BTreeMap, result};

/// Contains the information about which queries the
/// distributed system should run.
#[derive(Debug, Deserialize, Serialize)]
pub struct QueriesRequest {
    /// Map from query name to query SQL
    queries: BTreeMap<String, String>,

    /// Used for "discovery" queries in the distributed
    /// system. When used, discovery queries should be specified with query
    /// name as the key and the discover query SQL as the value. If this is
    /// nonempty, only queries for which the associated discovery query
    /// returns results will be run in osquery.
    #[serde(default)]
    discovery: BTreeMap<String, String>,

    /// Can be specified to have "accelerated" checkins
    /// for a given number of seconds after this checkin. Currently this
    /// means that checkins will occur every 5 seconds.
    #[serde(default, rename = "accelerate")]
    accelerate_seconds: i64,
}

impl QueriesRequest {
    /// Create a new queries request with the given queries map.
    #[must_use]
    pub fn new(queries: BTreeMap<String, String>) -> Self {
        Self {
            queries,
            discovery: BTreeMap::new(),
            accelerate_seconds: 5,
        }
    }

    /// Return the queries map.
    #[must_use]
    pub fn queries(&self) -> &BTreeMap<String, String> {
        &self.queries
    }

    /// Return the discovery queries map.
    #[must_use]
    pub fn discovery(&self) -> &BTreeMap<String, String> {
        &self.discovery
    }

    /// Return the accelerate seconds value.
    #[must_use]
    pub fn accelerate_seconds(&self) -> i64 {
        self.accelerate_seconds
    }

    /// Set the discovery queries.
    #[must_use]
    pub fn with_discovery(mut self, discovery: BTreeMap<String, String>) -> Self {
        self.discovery = discovery;
        self
    }

    /// Set the accelerate seconds value.
    #[must_use]
    pub fn with_accelerate_seconds(mut self, seconds: i64) -> Self {
        self.accelerate_seconds = seconds;
        self
    }
}

/// Contains the status and results for a distributed query.
#[derive(Debug, Default, Deserialize)]
pub struct QueryResponse {
    /// Name that was originally provided for the query.
    pub query_name: String,
    /// Status code for the query execution (0 = OK)
    pub status: i64,
    /// Result rows of the query.
    pub rows: Vec<BTreeMap<String, String>>,
    /// Stats about the execution of the given query.
    pub stats: Option<Stats>,
    /// Message string indicating the status of the query.
    #[serde(default)]
    pub message: String,
}

/// Holds performance stats about the execution of a given query.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    #[serde(default, deserialize_with = "deserialize_osquery_int")]
    pub wall_time_ms: i64,
    #[serde(default, deserialize_with = "deserialize_osquery_int")]
    pub user_time: i64,
    #[serde(default, deserialize_with = "deserialize_osquery_int")]
    pub system_time: i64,
    #[serde(default, deserialize_with = "deserialize_osquery_int")]
    pub memory: i64,
}

/// Handles deserializing integers in noncanonical osquery JSON.
/// osquery may encode integers as either JSON numbers or quoted strings.
fn deserialize_osquery_int<'de, D>(deserializer: D) -> result::Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    OsqueryInt::deserialize(deserializer).map(|oi| oi.0)
}

// Handles deserializing integers in noncanonical osquery JSON.
#[derive(Debug)]
struct OsqueryInt(i64);

impl From<i64> for OsqueryInt {
    fn from(inner: i64) -> Self {
        OsqueryInt(inner)
    }
}

impl From<OsqueryInt> for i64 {
    fn from(this: OsqueryInt) -> Self {
        this.0
    }
}

impl TryFrom<&str> for OsqueryInt {
    type Error = std::num::ParseIntError;
    fn try_from(value: &str) -> result::Result<Self, Self::Error> {
        Ok(OsqueryInt(value.parse::<i64>()?))
    }
}

impl<'de> Deserialize<'de> for OsqueryInt {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper: Value = Deserialize::deserialize(deserializer)?;
        match helper {
            // osquery < v3.0 with stringy types
            Value::String(s) if !s.is_empty() => {
                let op = s.parse::<i64>().map_err(de::Error::custom)?;
                Ok(OsqueryInt::from(op))
            }
            // osquery > v3.0 with strong types
            Value::Number(n) if n.is_i64() => {
                let op = n
                    .as_i64()
                    .ok_or_else(|| de::Error::custom("expected int"))?;
                Ok(OsqueryInt::from(op))
            }
            value => Err(de::Error::custom(format!(
                "invalid value {value}, expected int",
            ))),
        }
    }
}

/// Used for deserializing the results passed from osquery.
#[derive(Debug, Deserialize)]
struct QueriesResponse {
    queries: BTreeMap<String, Value>,
    statuses: BTreeMap<String, OsqueryInt>,
    #[serde(default)]
    stats: BTreeMap<String, Stats>,
    #[serde(default)]
    messages: BTreeMap<String, String>,
}

impl TryFrom<QueriesResponse> for Vec<QueryResponse> {
    type Error = String;

    fn try_from(this: QueriesResponse) -> result::Result<Self, Self::Error> {
        let QueriesResponse {
            queries,
            statuses,
            stats,
            messages,
        } = this;
        let mut responses = vec![];

        for (query_name, status) in statuses {
            let rows = match queries.get(&query_name) {
                Some(Value::Array(rows)) => serde_json::from_value(Value::Array(rows.clone()))
                    .map_err(|err| format!("{query_name}: {err}"))?,
                // Empty string results or missing query results are treated as empty rows
                Some(Value::String(_)) | None => vec![],
                Some(other) => {
                    return Err(format!("results for \"{query_name}\" unknown type {other}"));
                }
            };

            let query_stats = stats.get(&query_name).cloned();
            let message = messages.get(&query_name).cloned().unwrap_or_default();

            responses.push(QueryResponse {
                query_name,
                status: status.into(),
                rows,
                stats: query_stats,
                message,
            });
        }

        Ok(responses)
    }
}

/// Osquery distributed plugin. Implements the `OsqueryPlugin` interface.
pub struct DistributedPlugin<GetFunc, WriteFunc>
where
    GetFunc: FnMut() -> Result<QueriesRequest>,
    WriteFunc: FnMut(Vec<QueryResponse>) -> Result<()>,
{
    name: String,
    get_queries: GetFunc,
    write_queries: WriteFunc,
}

impl<GetFunc, WriteFunc> std::fmt::Debug for DistributedPlugin<GetFunc, WriteFunc>
where
    GetFunc: FnMut() -> Result<QueriesRequest>,
    WriteFunc: FnMut(Vec<QueryResponse>) -> Result<()>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DistributedPlugin")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<GetFunc, WriteFunc> DistributedPlugin<GetFunc, WriteFunc>
where
    GetFunc: FnMut() -> Result<QueriesRequest>,
    WriteFunc: FnMut(Vec<QueryResponse>) -> Result<()>,
{
    pub fn new(name: &str, get_queries: GetFunc, write_queries: WriteFunc) -> Self {
        Self {
            name: name.to_string(),
            get_queries,
            write_queries,
        }
    }
}

impl<GetFunc, WriteFunc> OsqueryPlugin for DistributedPlugin<GetFunc, WriteFunc>
where
    GetFunc: FnMut() -> Result<QueriesRequest> + Send + Sync,
    WriteFunc: FnMut(Vec<QueryResponse>) -> Result<()> + Send + Sync,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        RegistryName::Distributed
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.name))
    )]
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let result: Result<_> = match req.get("action") {
            // Call get_queries
            Some(action) if action == "getQueries" => {
                match (self.get_queries)() {
                    Ok(response) => match serde_json::to_string(&response) {
                        Ok(query_json) => Ok(osquery::ExtensionPluginResponse::from([
                            BTreeMap::from([("results".to_string(), query_json)]),
                        ])),
                        Err(err) => Err(format!("error serializing queries: {err}").into()),
                    },
                    Err(err) => Err(format!("error getting queries: {err}").into()),
                }
            }
            // Call write_queries
            Some(action) if action == "writeResults" => match req.get("results") {
                Some(results_json) => match serde_json::from_str::<QueriesResponse>(results_json) {
                    Ok(queries) => {
                        let query_resp: result::Result<Vec<QueryResponse>, _> = queries.try_into();
                        match query_resp {
                            Ok(results) => match (self.write_queries)(results) {
                                Ok(()) => Ok(osquery::ExtensionPluginResponse::default()),
                                Err(err) => Err(format!("error writing results: {err}").into()),
                            },
                            Err(err) => Err(format!("error writing results: {err}").into()),
                        }
                    }
                    Err(err) => Err(format!("error deserializing results: {err}").into()),
                },
                None => Err(String::from("error: missing results").into()),
            },
            Some(action) => Err(format!("unknown action: {action}").into()),
            None => Err(String::from("missing action").into()),
        };

        match result {
            Ok(resp) => osquery::ExtensionResponse::new(
                osquery::ExtensionStatus::new(0, String::from("OK"), None),
                resp,
            ),
            Err(err) => {
                let status = osquery::ExtensionStatus::new(1, err.to_string(), None);
                osquery::ExtensionResponse::new(status, None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributed_plugin() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            move || {
                Ok(QueriesRequest::new(BTreeMap::from([
                    (
                        "query1".to_string(),
                        "select iso_8601 from time".to_string(),
                    ),
                    (
                        "query2".to_string(),
                        "select version from osquery_info".to_string(),
                    ),
                    ("query3".to_string(), "select foo from bar".to_string()),
                ])))
            },
            move |res| {
                // 3 results: query1 (rows), query2 (rows), query3 (status only, empty rows)
                assert_eq!(res.len(), 3);
                assert_eq!(res[0].query_name, "query1");
                assert_eq!(res[0].status, 0);
                assert_eq!(
                    res[0].rows,
                    vec![BTreeMap::from([(
                        "iso_8601".to_string(),
                        "2017-07-10T22:08:40Z".to_string()
                    )])]
                );
                assert_eq!(res[1].query_name, "query2");
                assert_eq!(res[1].status, 0);
                assert_eq!(
                    res[1].rows,
                    vec![BTreeMap::from([(
                        "version".to_string(),
                        "2.4.0".to_string()
                    )])]
                );
                assert_eq!(res[2].query_name, "query3");
                assert_eq!(res[2].status, 1);
                assert!(res[2].rows.is_empty());
                Ok(())
            },
        );

        assert_eq!(plugin.name(), "mock");
        assert_eq!(plugin.registry_name(), RegistryName::Distributed);

        // Call getQueries
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert!(resp.response.is_some());

        assert!(resp.response.clone().unwrap()[0].contains_key("results"));
        assert_eq!(
            r#"{"queries":{"query1":"select iso_8601 from time","query2":"select version from osquery_info","query3":"select foo from bar"},"discovery":{},"accelerate":5}"#,
            resp.response.unwrap()[0].get("results").unwrap()
        );

        // Call writeResults with osquery < v3.0 with stringy types
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":"0","query2":"0","query3":"1"}}"#)),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
        // Call writeResults with osquery > v3.0 with strong types
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":0,"query2":0,"query3":1}}"#)),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
    }

    #[test]
    fn distributed_plugin_accelerate_discovery() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            move || {
                Ok(QueriesRequest::new(BTreeMap::from([(
                    "query1".to_string(),
                    "select * from time".to_string(),
                )]))
                .with_discovery(BTreeMap::from([(
                    "query1".to_string(),
                    r#"select version from osquery_info where version = "2.4.0""#.to_string(),
                )]))
                .with_accelerate_seconds(30))
            },
            move |_| Ok(()),
        );
        // Call getQueries
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert!(resp.response.is_some());
        assert_eq!(resp.response.clone().unwrap().len(), 1);
        assert_eq!(
            *resp
                .response
                .unwrap().first()
                .unwrap()
                .get("results")
                .unwrap(),
            r#"{"queries":{"query1":"select * from time"},"discovery":{"query1":"select version from osquery_info where version = \"2.4.0\""},"accelerate":30}"#.to_string()
        );
    }

    #[test]
    fn distributed_plugin_errors() {
        let mut plugin = DistributedPlugin::new(
            "mock",
            || Err("getQueries failed".into()),
            |_| Err("writeResults failed".into()),
        );
        // Call with bad actions
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("bad"),
        )]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "unknown action: bad".to_string()
        );

        // Call with good action but getQueries fails
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error getting queries: getQueries failed".to_string()
        );
        // Call with good action but bad results
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(r#"{"statuses": {"query1": "foo"}}"#),
            ),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error deserializing results: invalid digit found in string at line 1 column 30"
                .to_string()
        );
        // Call with good action but bad status type
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(r#"{"statuses": {"query1": []}}"#),
            ),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error deserializing results: invalid value [], expected int at line 1 column 27"
                .to_string()
        );
        // Call with good action but missing queries field
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (String::from("results"), String::from(r#"{"statuses": {}}"#)),
        ]));
        assert!(resp.response.is_none());
        assert!(resp.status.is_some());
        assert_eq!(resp.status.clone().unwrap().code.unwrap_or(0), 1);
        assert_eq!(
            resp.status.unwrap().message.unwrap(),
            "error deserializing results: missing field `queries` at line 1 column 16".to_string()
        )
    }

    #[test]
    fn distributed_plugin_with_stats_and_messages() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            || Ok(QueriesRequest::new(BTreeMap::new())),
            |res| {
                assert_eq!(res.len(), 1);
                assert_eq!(res[0].query_name, "q1");
                assert_eq!(res[0].status, 0);
                let stats = res[0].stats.as_ref().unwrap();
                assert_eq!(stats.wall_time_ms, 42);
                assert_eq!(stats.user_time, 10);
                assert_eq!(stats.system_time, 5);
                assert_eq!(stats.memory, 1024);
                assert_eq!(res[0].message, "completed");
                Ok(())
            },
        );
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(
                    r#"{"queries":{"q1":[{"col":"val"}]},"statuses":{"q1":0},"stats":{"q1":{"wall_time_ms":42,"user_time":10,"system_time":5,"memory":1024}},"messages":{"q1":"completed"}}"#,
                ),
            ),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
    }

    #[test]
    fn distributed_plugin_with_stringy_stats() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            || Ok(QueriesRequest::new(BTreeMap::new())),
            |res| {
                assert_eq!(res.len(), 1);
                let stats = res[0].stats.as_ref().unwrap();
                assert_eq!(stats.wall_time_ms, 100);
                assert_eq!(stats.user_time, 20);
                Ok(())
            },
        );
        // Stats with stringy ints (osquery < v3)
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(
                    r#"{"queries":{"q1":[]},"statuses":{"q1":"0"},"stats":{"q1":{"wall_time_ms":"100","user_time":"20","system_time":"0","memory":"0"}}}"#,
                ),
            ),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
    }

    #[test]
    fn distributed_empty_string_results() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut plugin = DistributedPlugin::new(
            "mock",
            || Ok(QueriesRequest::new(BTreeMap::new())),
            |res| {
                assert_eq!(res.len(), 2);
                // q1 has empty string result -> empty rows
                assert_eq!(res[0].query_name, "q1");
                assert!(res[0].rows.is_empty());
                // q2 has array result
                assert_eq!(res[1].query_name, "q2");
                assert_eq!(res[1].rows.len(), 1);
                Ok(())
            },
        );
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("writeResults")),
            (
                String::from("results"),
                String::from(
                    r#"{"queries":{"q1":"","q2":[{"c":"v"}]},"statuses":{"q1":0,"q2":0}}"#,
                ),
            ),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
    }

    #[test]
    fn distributed_closure_captures_state() {
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let mut plugin = DistributedPlugin::new(
            "mock",
            || {
                call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(QueriesRequest::new(BTreeMap::from([(
                    "q1".to_string(),
                    "select 1".to_string(),
                )])))
            },
            |_| Ok(()),
        );
        // Verify closures work (not just fn pointers)
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("getQueries"),
        )]));
        assert_eq!(resp.status.unwrap().code.unwrap(), 0);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn deserialize_response() {
        const RAW_JSON_QUERY: &str = r#"{"queries":{"detail_query_network_interface":[{"interface":"en0","mac":"78:4f:43:9c:3c:8d","type":"","mtu":"1500","metric":"0","ipackets":"7071136","opackets":"6408727","ibytes":"1481456771","obytes":"1633052673","ierrors":"0","oerrors":"0","idrops":"0","odrops":"0","last_change":"1501077669","description":"","manufacturer":"","connection_id":"","connection_status":"","enabled":"","physical_adapter":"","speed":"","dhcp_enabled":"","dhcp_lease_expires":"","dhcp_lease_obtained":"","dhcp_server":"","dns_domain":"","dns_domain_suffix_search_order":"","dns_host_name":"","dns_server_search_order":"","interface":"en0","address":"192.168.1.135","mask":"255.255.255.0","broadcast":"192.168.1.255","point_to_point":"","type":""}],"detail_query_os_version":[{"name":"Mac OS X","version":"10.12.6","major":"10","minor":"12","patch":"6","build":"16G29","platform":"darwin","platform_like":"darwin","codename":""}],"detail_query_osquery_flags":[{"name":"config_refresh","value":"10"},{"name":"distributed_interval","value":"10"},{"name":"logger_tls_period","value":"10"}],"detail_query_osquery_info":[{"pid":"75680","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","instance_id":"89f267fa-9a17-4a73-87d6-05197491f2e8","version":"2.5.0","config_hash":"960121acb9bcbb136ce49fe77000752f237fd0dd","config_valid":"1","extensions":"active","build_platform":"darwin","build_distro":"10.12","start_time":"1502371429","watcher":"75678"}],"detail_query_system_info":[{"hostname":"Johns-MacBook-Pro.local","uuid":"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C","cpu_type":"x86_64h","cpu_subtype":"Intel x86-64h Haswell","cpu_brand":"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz","cpu_physical_cores":"4","cpu_logical_cores":"8","physical_memory":"17179869184","hardware_vendor":"Apple Inc.","hardware_model":"MacBookPro13,3","hardware_version":"1.0","hardware_serial":"C02SP067H040","computer_name":"","local_hostname":"Johns-MacBook-Pro"}],"detail_query_uptime":[{"days":"21","hours":"18","minutes":"29","seconds":"18","total_seconds":"1893778"}]},"statuses":{"detail_query_network_interface":0,"detail_query_os_version":0,"detail_query_osquery_flags":0,"detail_query_osquery_info":0,"detail_query_system_info":0,"detail_query_uptime":0,"detail_query_schedule":0}}"#;
        let queries: QueriesResponse = serde_json::from_str(RAW_JSON_QUERY).unwrap();
        let resp: result::Result<Vec<QueryResponse>, _> = queries.try_into();
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().len(), 7);
    }

    #[test]
    fn deserialize_status() {
        // should_fail, data, expected
        let test_cases = vec![
            // from str
            (false, r#"{"status": "0"}"#, OsqueryInt(0)),
            (false, r#"{"status": "1"}"#, OsqueryInt(1)),
            (false, r#"{"status": "000"}"#, OsqueryInt(0)),
            (false, r#"{"status": "-12"}"#, OsqueryInt(-12)),
            // from int
            (false, r#"{"status": 0}"#, OsqueryInt(0)),
            (false, r#"{"status": 1}"#, OsqueryInt(1)),
            (false, r#"{"status": -12}"#, OsqueryInt(-12)),
            // should fail
            (true, r"foo", OsqueryInt(0)),
            (true, r#"{"status": ""}"#, OsqueryInt(0)),
            (true, r#"{"status": 000}"#, OsqueryInt(0)),
            (
                true,
                r#"{"status": "9223372036854775807887766554433"}"#,
                OsqueryInt(0),
            ),
            (
                true,
                r#"{"status": 9223372036854775807887766554433}"#,
                OsqueryInt(0),
            ),
            (true, r#"{"status": []}"#, OsqueryInt(0)),
        ];
        for (should_err, data, expected) in test_cases {
            let status: result::Result<BTreeMap<String, OsqueryInt>, _> =
                serde_json::from_str(data);
            match status {
                Ok(s) => {
                    assert!(!should_err);
                    assert_eq!(expected.0, s.get("status").unwrap().0);
                }
                Err(err) => {
                    println!("{err:?}");
                    assert!(should_err);
                }
            }
        }
        let stat: i64 = OsqueryInt(12).into();
        assert_eq!(12, stat);
    }
}
