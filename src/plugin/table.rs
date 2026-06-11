//! Create an osquery table plugin.

use crate::{OsqueryPlugin, RegistryName, Result, osquery};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, result};

/// An osquery table map.
pub type Table = Vec<BTreeMap<String, String>>;

/// Column values from a mutation request, in column-definition order.
/// `None` represents a SQL `NULL` value.
pub type ColumnValues = Vec<Option<String>>;

/// Request payload for a `DELETE` action on a writable table.
///
/// Sent by osquery when a `DELETE FROM <table> WHERE ...` statement targets
/// a specific row identified by its `SQLite` rowid.
#[derive(Clone, Debug)]
pub struct DeleteRequest {
    /// The `SQLite` row ID of the row to delete.
    pub row_id: i64,
    /// Query context from osquery (WHERE constraints).
    pub context: QueryContext,
}

/// Request payload for an `INSERT` action on a writable table.
///
/// Sent by osquery when an `INSERT INTO <table> ...` statement adds a new row.
/// The `values` are in column-definition order (matching the columns passed to
/// [`TablePlugin::new`]).
#[derive(Clone, Debug)]
pub struct InsertRequest {
    /// Column values in column-definition order. `None` = SQL `NULL`.
    pub values: ColumnValues,
    /// Whether osquery assigned the row ID automatically.
    pub auto_rowid: bool,
    /// The suggested row ID. `None` when `auto_rowid` is true and osquery
    /// has not assigned one yet.
    pub row_id: Option<i64>,
    /// Query context from osquery.
    pub context: QueryContext,
}

/// Request payload for an `UPDATE` action on a writable table.
///
/// Sent by osquery when an `UPDATE <table> SET ... WHERE ...` statement
/// modifies an existing row.
#[derive(Clone, Debug)]
pub struct UpdateRequest {
    /// The current row ID of the row being updated.
    pub row_id: i64,
    /// The new row ID, if the update changes it. `None` when unchanged.
    pub new_row_id: Option<i64>,
    /// New column values in column-definition order. `None` = SQL `NULL`.
    pub values: ColumnValues,
    /// Query context from osquery.
    pub context: QueryContext,
}

/// Result of a mutation operation on a writable table.
///
/// Each variant maps to a specific `SQLite` result code that osquery
/// translates back to the query engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationResult {
    /// The operation succeeded (`SQLITE_OK`). For `INSERT`, `row_id` is the
    /// assigned row ID to return to `SQLite` (if any).
    Success {
        /// The assigned row ID, typically set for INSERT operations.
        row_id: Option<i64>,
    },
    /// The table is read-only and does not support this operation (`SQLITE_READONLY`).
    ReadOnly,
    /// The operation failed with the given error message (`SQLITE_ERROR`).
    Failure(String),
    /// A constraint violation occurred (`SQLITE_CONSTRAINT`).
    Constraint,
}

/// Error returned when an integer does not map to a known [`Operator`] variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidOperator(pub i64);

impl fmt::Display for InvalidOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid operator value: {}", self.0)
    }
}

impl std::error::Error for InvalidOperator {}

/// Read-only osquery table plugin.
///
/// For writable tables (INSERT/UPDATE/DELETE), implement [`WritableTable`]
/// and wrap it in [`WritableTablePlugin`].
pub struct TablePlugin<GenFunc: FnMut(QueryContext) -> Result<Table>> {
    name: String,
    columns: Vec<ColumnDefinition>,
    generate: GenFunc,
    description: String,
    url: String,
    notes: String,
    examples: Vec<String>,
    platforms: Vec<Platform>,
}

/// Platform names for table spec generation.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum Platform {
    #[serde(rename = "darwin")]
    Darwin,
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "linux")]
    Linux,
}

/// Returns the platform for the current OS.
fn default_platform() -> Vec<Platform> {
    if cfg!(target_os = "macos") {
        vec![Platform::Darwin]
    } else if cfg!(target_os = "windows") {
        vec![Platform::Windows]
    } else if cfg!(target_os = "linux") {
        vec![Platform::Linux]
    } else {
        vec![]
    }
}

/// Osquery table spec, compatible with osquery spec files. Can be serialized to JSON.
#[derive(Debug, Serialize)]
pub struct OsqueryTableSpec {
    pub name: String,
    pub description: String,
    pub url: String,
    pub platforms: Vec<Platform>,
    pub evented: bool,
    pub cacheable: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    pub columns: Vec<ColumnDefinition>,
}

/// Strongly typed column data type. Values correspond to osquery's column type strings.
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ColumnType {
    Unknown,
    Text,
    Integer,
    BigInt,
    #[serde(rename = "UNSIGNED BIGINT")]
    UnsignedBigInt,
    Double,
    Blob,
}

impl fmt::Display for ColumnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ColumnType::Unknown => write!(f, "UNKNOWN"),
            ColumnType::Text => write!(f, "TEXT"),
            ColumnType::Integer => write!(f, "INTEGER"),
            ColumnType::BigInt => write!(f, "BIGINT"),
            ColumnType::UnsignedBigInt => write!(f, "UNSIGNED BIGINT"),
            ColumnType::Double => write!(f, "DOUBLE"),
            ColumnType::Blob => write!(f, "BLOB"),
        }
    }
}

impl Serialize for ColumnType {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Lowercase with underscores, matching osquery-go's MarshalJSON.
        let s = match self {
            ColumnType::Unknown => "unknown",
            ColumnType::Text => "text",
            ColumnType::Integer => "integer",
            ColumnType::BigInt => "bigint",
            ColumnType::UnsignedBigInt => "unsigned_bigint",
            ColumnType::Double => "double",
            ColumnType::Blob => "blob",
        };
        serializer.serialize_str(s)
    }
}

/// `QueryContext` contains the constraints from the WHERE clause of the query,
/// that can optionally be used to optimize the table generation. Note that the
/// osquery `SQLite` engine will perform the filtering with these constraints, so
/// it is not mandatory that they be used in table generation.
///
/// Provides accessor methods for the underlying constraint map keyed by column name.
#[derive(Clone, Debug, Default, PartialEq)]

pub struct QueryContext(BTreeMap<String, ConstraintList>);

impl QueryContext {
    /// Return the constraint list for the given column name, if present.
    #[must_use]
    pub fn get(&self, column: &str) -> Option<&ConstraintList> {
        self.0.get(column)
    }

    /// Return whether the context contains constraints for the given column.
    #[must_use]
    pub fn contains_key(&self, column: &str) -> bool {
        self.0.contains_key(column)
    }

    /// Return the number of columns with constraints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether there are no column constraints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the column constraints.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ConstraintList)> {
        self.0.iter()
    }

    /// Return a mutable reference to the constraint list for the given column,
    /// inserting a default if not present.
    pub fn entry(
        &mut self,
        column: String,
    ) -> std::collections::btree_map::Entry<'_, String, ConstraintList> {
        self.0.entry(column)
    }

    /// Insert a constraint list for the given column.
    pub fn insert(&mut self, column: String, list: ConstraintList) -> Option<ConstraintList> {
        self.0.insert(column, list)
    }
}

impl<'de> Deserialize<'de> for QueryContext {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut constraints = BTreeMap::new();
        let helper: Value = Deserialize::deserialize(deserializer)?;
        match &helper["constraints"] {
            Value::Array(raw_constraints) => {
                for constraint in raw_constraints {
                    match &constraint["name"] {
                        Value::String(name) => {
                            constraints.insert(
                                name.clone(),
                                serde_json::from_value::<ConstraintList>(constraint.clone())
                                    .map_err(de::Error::custom)?,
                            );
                        }
                        other => {
                            return Err(de::Error::custom(format!(
                                "name: invalid value {other}, expected string"
                            )));
                        }
                    }
                }
                Ok(QueryContext(constraints))
            }
            Value::Null => Ok(QueryContext(constraints)),
            other => Err(de::Error::custom(format!(
                "constraints: invalid value {other}, expected array"
            ))),
        }
    }
}

/// Column constraints with type affinity and a list of individual constraints.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ConstraintList {
    affinity: ColumnType,
    #[serde(default, rename = "list", deserialize_with = "de_constraint_list")]
    constraints: Vec<Constraint>,
}

impl ConstraintList {
    #[must_use]
    pub fn affinity(&self) -> &ColumnType {
        &self.affinity
    }

    #[must_use]
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }
}

fn de_constraint_list<'de, D>(deserializer: D) -> result::Result<Vec<Constraint>, D::Error>
where
    D: Deserializer<'de>,
{
    let helper: Value = Deserialize::deserialize(deserializer)?;
    match helper {
        // string indicates empty list in osquery
        Value::String(s) if s.is_empty() => Ok(Vec::new()),
        Value::Array(items) => Ok(items
            .into_iter()
            // Skip unparseable constraints: osquery re-applies the WHERE
            // clause anyway, so dropping a pushdown hint is safe.
            .filter_map(|item| match serde_json::from_value::<Constraint>(item) {
                Ok(constraint) => Some(constraint),
                #[cfg(feature = "tracing")]
                Err(err) => {
                    tracing::warn!("skipping unparseable constraint: {err}");
                    None
                }
                #[cfg(not(feature = "tracing"))]
                Err(_) => None,
            })
            .collect()),
        val => Err(de::Error::custom(format!(
            "unexpected context list: invalid value {val}, expected array"
        ))),
    }
}

/// A single constraint pairing an [`Operator`] with an expression value.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Constraint {
    #[serde(rename = "op")]
    operator: Operator,
    #[serde(rename = "expr")]
    expression: String,
}

impl Constraint {
    #[must_use]
    pub fn operator(&self) -> &Operator {
        &self.operator
    }

    #[must_use]
    pub fn expression(&self) -> &str {
        self.expression.as_ref()
    }
}

/// osquery WHERE-clause operators. Values match osquery `tables.h`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operator {
    Equals = 2,
    GreaterThan = 4,
    LessThanOrEquals = 8,
    LessThan = 16,
    GreaterThanOrEquals = 32,
    Match = 64,
    Like = 65,
    Glob = 66,
    Regexp = 67,
    Unique = 1,
    In = 3,
    NotEquals = 68,
    IsNot = 69,
    IsNotNull = 70,
    IsNull = 71,
    Is = 72,
    Limit = 73,
    Offset = 74,
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operator::Equals => write!(f, "="),
            Operator::GreaterThan => write!(f, ">"),
            Operator::LessThanOrEquals => write!(f, "<="),
            Operator::LessThan => write!(f, "<"),
            Operator::GreaterThanOrEquals => write!(f, ">="),
            Operator::Match => write!(f, "MATCH"),
            Operator::Like => write!(f, "LIKE"),
            Operator::Glob => write!(f, "GLOB"),
            Operator::Regexp => write!(f, "REGEXP"),
            Operator::Unique => write!(f, "UNIQUE"),
            Operator::In => write!(f, "IN"),
            Operator::NotEquals => write!(f, "!="),
            Operator::IsNot => write!(f, "IS NOT"),
            Operator::IsNotNull => write!(f, "IS NOT NULL"),
            Operator::IsNull => write!(f, "IS NULL"),
            Operator::Is => write!(f, "IS"),
            Operator::Limit => write!(f, "LIMIT"),
            Operator::Offset => write!(f, "OFFSET"),
        }
    }
}

impl<'de> Deserialize<'de> for Operator {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper: Value = Deserialize::deserialize(deserializer)?;
        match helper {
            // osquery < v3.0 with stringy types
            Value::String(s) if !s.is_empty() => {
                let op = s.parse::<i64>().map_err(de::Error::custom)?;
                Operator::try_from(op).map_err(de::Error::custom)
            }
            // osquery > v3.0 with strong types
            Value::Number(n) if n.is_i64() => {
                let op = n
                    .as_i64()
                    .ok_or_else(|| de::Error::custom("expected an int"))?;
                Operator::try_from(op).map_err(de::Error::custom)
            }
            value => Err(de::Error::custom(format!(
                "invalid value {value}, expected int",
            ))),
        }
    }
}

impl TryFrom<i64> for Operator {
    type Error = InvalidOperator;
    fn try_from(value: i64) -> result::Result<Self, Self::Error> {
        match value {
            2 => Ok(Operator::Equals),
            4 => Ok(Operator::GreaterThan),
            8 => Ok(Operator::LessThanOrEquals),
            16 => Ok(Operator::LessThan),
            32 => Ok(Operator::GreaterThanOrEquals),
            64 => Ok(Operator::Match),
            65 => Ok(Operator::Like),
            66 => Ok(Operator::Glob),
            67 => Ok(Operator::Regexp),
            1 => Ok(Operator::Unique),
            3 => Ok(Operator::In),
            68 => Ok(Operator::NotEquals),
            69 => Ok(Operator::IsNot),
            70 => Ok(Operator::IsNotNull),
            71 => Ok(Operator::IsNull),
            72 => Ok(Operator::Is),
            73 => Ok(Operator::Limit),
            74 => Ok(Operator::Offset),
            _ => Err(InvalidOperator(value)),
        }
    }
}

/// `ColumnDefinition` defines the relevant information for a column in a table plugin.
/// Name and Type are mandatory. Use `new` or the type-specific helpers (`text`, `integer`, etc.)
/// followed by builder methods to configure column options.
///
/// # Example
/// ```
/// use osquery_rs_sdk::plugin::table::{ColumnDefinition, ColumnType};
/// let col = ColumnDefinition::new("uid", ColumnType::Integer)
///     .index()
///     .required()
///     .with_description("User ID");
/// ```
#[derive(Clone, Debug, Serialize)]
pub struct ColumnDefinition {
    name: String,
    #[serde(rename = "type")]
    col_type: ColumnType,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    notes: String,
    // Column options from osquery column.h
    index: bool,
    required: bool,
    additional: bool,
    optimized: bool,
    hidden: bool,
}

impl Default for ColumnDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            col_type: ColumnType::Text,
            description: String::new(),
            notes: String::new(),
            index: false,
            required: false,
            additional: false,
            optimized: false,
            hidden: false,
        }
    }
}

impl ColumnDefinition {
    /// Create a column with the given name and type.
    #[must_use]
    pub fn new(name: &str, col_type: ColumnType) -> Self {
        Self {
            name: name.to_string(),
            col_type,
            description: String::new(),
            notes: String::new(),
            index: false,
            required: false,
            additional: false,
            optimized: false,
            hidden: false,
        }
    }

    /// Create a `TEXT` column.
    #[must_use]
    pub fn text(name: &str) -> Self {
        Self::new(name, ColumnType::Text)
    }

    /// Create an `INTEGER` column.
    #[must_use]
    pub fn integer(name: &str) -> Self {
        Self::new(name, ColumnType::Integer)
    }

    /// Create a `BIGINT` column.
    #[must_use]
    pub fn big_int(name: &str) -> Self {
        Self::new(name, ColumnType::BigInt)
    }

    /// Create an `UNSIGNED BIGINT` column.
    #[must_use]
    pub fn unsigned_big_int(name: &str) -> Self {
        Self::new(name, ColumnType::UnsignedBigInt)
    }

    /// Create a `DOUBLE` column.
    #[must_use]
    pub fn double(name: &str) -> Self {
        Self::new(name, ColumnType::Double)
    }

    /// Create a `BLOB` column.
    #[must_use]
    pub fn blob(name: &str) -> Self {
        Self::new(name, ColumnType::Blob)
    }

    /// Mark as an index column. Can significantly change query performance.
    #[must_use]
    pub fn index(mut self) -> Self {
        self.index = true;
        self
    }

    /// Mark as required. `SQLite` will reject queries missing this column.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Mark as additional.
    #[must_use]
    pub fn additional(mut self) -> Self {
        self.additional = true;
        self
    }

    /// Mark as optimized.
    #[must_use]
    pub fn optimized(mut self) -> Self {
        self.optimized = true;
        self
    }

    /// Mark as hidden. Omits this column from `SELECT *` queries.
    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Bitmask of column options (osquery `column.h`: Index=1, Required=2,
    /// Additional=4, Optimized=8, Hidden=16).
    #[must_use]
    pub fn options(&self) -> u8 {
        let mut mask: u8 = 0;
        if self.index {
            mask |= 1;
        }
        if self.required {
            mask |= 2;
        }
        if self.additional {
            mask |= 4;
        }
        if self.optimized {
            mask |= 8;
        }
        if self.hidden {
            mask |= 16;
        }
        mask
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set the notes.
    #[must_use]
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = notes.to_string();
        self
    }
}

impl<GenFunc: FnMut(QueryContext) -> Result<Table>> TablePlugin<GenFunc> {
    /// Create a read-only `TablePlugin`.
    ///
    /// `generate` returns a [`Result<Table>`] containing the rows produced by
    /// the table for the given [`QueryContext`].
    ///
    /// For writable tables, implement the [`WritableTable`] trait instead.
    pub fn new(name: &str, columns: Vec<ColumnDefinition>, generate: GenFunc) -> Self {
        Self {
            name: name.to_string(),
            columns,
            generate,
            description: String::new(),
            url: String::new(),
            notes: String::new(),
            examples: Vec::new(),
            platforms: default_platform(),
        }
    }

    /// Set the table description for spec generation.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the table URL for spec generation.
    #[must_use]
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Set the table notes for spec generation.
    #[must_use]
    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// Add an example query for spec generation.
    #[must_use]
    pub fn example(mut self, example: impl Into<String>) -> Self {
        self.examples.push(example.into());
        self
    }

    /// Override the default platform(s).
    #[must_use]
    pub fn platforms(mut self, platforms: Vec<Platform>) -> Self {
        self.platforms = platforms;
        self
    }

    /// Generate the osquery table spec.
    pub fn spec(&self) -> OsqueryTableSpec {
        OsqueryTableSpec {
            name: self.name.clone(),
            description: self.description.clone(),
            url: self.url.clone(),
            platforms: self.platforms.clone(),
            evented: false,
            cacheable: false,
            notes: self.notes.clone(),
            examples: self.examples.clone(),
            columns: self.columns.clone(),
        }
    }
}

/// Parse osquery's `json_value_array` (`["val1", null, "val3"]`) into
/// column values. Non-null elements become `Some(String)`; JSON null
/// becomes `None`.
fn parse_json_value_array(json: &str) -> Result<ColumnValues> {
    let arr: Vec<Value> = serde_json::from_str(json)
        .map_err(|e| crate::Error::Other(format!("invalid json_value_array: {e}")))?;
    Ok(arr
        .into_iter()
        .map(|v| match v {
            Value::Null => None,
            Value::String(s) => Some(s),
            other => Some(other.to_string()),
        })
        .collect())
}

/// Build an [`ExtensionResponse`](osquery::ExtensionResponse) from a [`MutationResult`],
/// mapping each variant to its osquery wire-format status string.
fn mutation_response(result: MutationResult) -> osquery::ExtensionResponse {
    let ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
    let mut row = BTreeMap::new();
    match result {
        MutationResult::Success { row_id } => {
            row.insert("status".to_string(), "success".to_string());
            if let Some(id) = row_id {
                row.insert("id".to_string(), id.to_string());
            }
        }
        MutationResult::ReadOnly => {
            row.insert("status".to_string(), "readonly".to_string());
        }
        MutationResult::Failure(msg) => {
            row.insert("status".to_string(), "failure".to_string());
            if !msg.is_empty() {
                row.insert("message".to_string(), msg);
            }
        }
        MutationResult::Constraint => {
            row.insert("status".to_string(), "constraint".to_string());
        }
    }
    osquery::ExtensionResponse::new(ok, vec![row])
}

/// Parse a row ID field from a request map as `i64`.
fn parse_row_id(req: &osquery::ExtensionPluginRequest, key: &str) -> Result<i64> {
    req.get(key)
        .ok_or_else(|| crate::Error::Other(format!("missing {key}")))?
        .parse::<i64>()
        .map_err(|e| crate::Error::Other(format!("invalid {key}: {e}")))
}

/// Parse the `"context"` field into a [`QueryContext`], falling back to
/// an empty context on missing or malformed JSON.
fn parse_mutation_context(req: &osquery::ExtensionPluginRequest) -> QueryContext {
    req.get("context")
        .and_then(|s| serde_json::from_str::<QueryContext>(s).ok())
        .unwrap_or_default()
}

/// Build the route advertisement for a set of column definitions.
fn build_routes(columns: &[ColumnDefinition]) -> osquery::ExtensionPluginResponse {
    let mut routes = osquery::ExtensionPluginResponse::new();
    for col in columns {
        routes.push(BTreeMap::from([
            (String::from("id"), String::from("column")),
            (String::from("name"), col.name.clone()),
            (String::from("type"), col.col_type.to_string()),
            (String::from("op"), col.options().to_string()),
        ]));
    }
    routes
}

/// Dispatch the `"generate"` action: parse context JSON, call the generate
/// function, and wrap the result in an `ExtensionResponse`.
fn handle_generate(
    req: &osquery::ExtensionPluginRequest,
    generate: impl FnOnce(QueryContext) -> Result<Table>,
) -> osquery::ExtensionResponse {
    let ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
    match req.get("context") {
        Some(s) => match serde_json::from_str::<QueryContext>(s) {
            Ok(ctx) => match generate(ctx) {
                Ok(table) => osquery::ExtensionResponse::new(ok, table),
                Err(err) => {
                    let msg = format!("error generating table: {err}");
                    #[cfg(feature = "tracing")]
                    tracing::error!("{}", msg);
                    error_response(&msg)
                }
            },
            Err(err) => {
                let msg = format!("error parsing context JSON: {err}");
                #[cfg(feature = "tracing")]
                tracing::error!("{}", msg);
                error_response(&msg)
            }
        },
        None => error_response("missing query context"),
    }
}

/// Extract and parse the `json_value_array` field from a request, returning
/// an error response on failure.
fn extract_column_values(
    req: &osquery::ExtensionPluginRequest,
    action: &str,
) -> result::Result<ColumnValues, osquery::ExtensionResponse> {
    match req.get("json_value_array") {
        Some(s) => match parse_json_value_array(s) {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = format!("{action}: {e}");
                #[cfg(feature = "tracing")]
                tracing::error!("{}", msg);
                Err(mutation_response(MutationResult::Failure(msg)))
            }
        },
        None => Err(mutation_response(MutationResult::Failure(
            "missing json_value_array".to_string(),
        ))),
    }
}

/// Call a mutation callback and wrap the result in an `ExtensionResponse`.
fn dispatch_mutation(action: &str, result: Result<MutationResult>) -> osquery::ExtensionResponse {
    match result {
        Ok(r) => mutation_response(r),
        Err(e) => {
            let msg = format!("{action} failed: {e}");
            #[cfg(feature = "tracing")]
            tracing::error!("{}", msg);
            mutation_response(MutationResult::Failure(msg))
        }
    }
}

/// Build an error `ExtensionResponse` with status code 1.
fn error_response(msg: &str) -> osquery::ExtensionResponse {
    osquery::ExtensionResponse::new(
        osquery::ExtensionStatus::new(1, msg.to_string(), None),
        None,
    )
}

/// Trait for osquery tables that support INSERT, UPDATE, and DELETE.
///
/// Implement this on a struct that holds your table's state, then wrap it
/// with [`WritableTablePlugin`] for registration:
///
/// ```
/// # use osquery_rs_sdk::plugin::table::*;
/// # use osquery_rs_sdk::Result;
/// struct KvStore { data: std::collections::BTreeMap<i64, (String, String)> }
///
/// impl WritableTable for KvStore {
///     fn name(&self) -> &str { "kv_store" }
///     fn columns(&self) -> Vec<ColumnDefinition> {
///         vec![ColumnDefinition::text("key"), ColumnDefinition::text("value")]
///     }
///     fn generate(&mut self, _ctx: QueryContext) -> Result<Table> { Ok(vec![]) }
///     fn insert(&mut self, _req: InsertRequest) -> Result<MutationResult> {
///         Ok(MutationResult::Success { row_id: None })
///     }
///     fn update(&mut self, _req: UpdateRequest) -> Result<MutationResult> {
///         Ok(MutationResult::Success { row_id: None })
///     }
///     fn delete(&mut self, _req: DeleteRequest) -> Result<MutationResult> {
///         Ok(MutationResult::Success { row_id: None })
///     }
/// }
/// ```
#[allow(clippy::missing_errors_doc)] // Error conditions are implementor-defined.
pub trait WritableTable: Send + Sync {
    /// Table name as registered with osquery.
    fn name(&self) -> &str;

    /// Column definitions for this table.
    fn columns(&self) -> Vec<ColumnDefinition>;

    /// Generate rows for a SELECT query.
    fn generate(&mut self, ctx: QueryContext) -> Result<Table>;

    /// Handle an INSERT statement.
    fn insert(&mut self, req: InsertRequest) -> Result<MutationResult>;

    /// Handle an UPDATE statement.
    fn update(&mut self, req: UpdateRequest) -> Result<MutationResult>;

    /// Handle a DELETE statement.
    fn delete(&mut self, req: DeleteRequest) -> Result<MutationResult>;
}

/// Wraps a [`WritableTable`] implementation as an [`OsqueryPlugin`] for
/// registration with [`ExtensionManagerServer`](crate::ExtensionManagerServer).
///
/// # Example
///
/// ```no_run
/// # use osquery_rs_sdk::{ExtensionManagerServer, plugin::table::*};
/// # struct MyTable;
/// # impl WritableTable for MyTable {
/// #     fn name(&self) -> &str { "my_table" }
/// #     fn columns(&self) -> Vec<ColumnDefinition> { vec![] }
/// #     fn generate(&mut self, _: QueryContext) -> osquery_rs_sdk::Result<Table> { Ok(vec![]) }
/// #     fn insert(&mut self, _: InsertRequest) -> osquery_rs_sdk::Result<MutationResult> { Ok(MutationResult::Success { row_id: None }) }
/// #     fn update(&mut self, _: UpdateRequest) -> osquery_rs_sdk::Result<MutationResult> { Ok(MutationResult::Success { row_id: None }) }
/// #     fn delete(&mut self, _: DeleteRequest) -> osquery_rs_sdk::Result<MutationResult> { Ok(MutationResult::Success { row_id: None }) }
/// # }
/// let mut server = ExtensionManagerServer::new("my_ext", "/var/osquery/osquery.em")?;
/// server.register_plugin(WritableTablePlugin::new(MyTable))?;
/// # Ok::<(), osquery_rs_sdk::Error>(())
/// ```
pub struct WritableTablePlugin<T: WritableTable> {
    inner: T,
}

impl<T: WritableTable> WritableTablePlugin<T> {
    /// Wrap a [`WritableTable`] implementation for plugin registration.
    pub fn new(table: T) -> Self {
        Self { inner: table }
    }
}

impl<T: WritableTable> WritableTablePlugin<T> {
    fn handle_insert(
        &mut self,
        req: &osquery::ExtensionPluginRequest,
    ) -> osquery::ExtensionResponse {
        let json_values = match extract_column_values(req, "insert") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let auto_rowid = req
            .get("auto_rowid")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let row_id = req.get("id").and_then(|s| s.parse::<i64>().ok());
        let context = parse_mutation_context(req);

        let request = InsertRequest {
            values: json_values,
            auto_rowid,
            row_id,
            context,
        };
        dispatch_mutation("insert", self.inner.insert(request))
    }

    fn handle_update(
        &mut self,
        req: &osquery::ExtensionPluginRequest,
    ) -> osquery::ExtensionResponse {
        let row_id = match parse_row_id(req, "id") {
            Ok(id) => id,
            Err(e) => {
                return mutation_response(MutationResult::Failure(format!("update: {e}")));
            }
        };
        let json_values = match extract_column_values(req, "update") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let new_row_id = req.get("new_id").and_then(|s| s.parse::<i64>().ok());
        let context = parse_mutation_context(req);

        let request = UpdateRequest {
            row_id,
            new_row_id,
            values: json_values,
            context,
        };
        dispatch_mutation("update", self.inner.update(request))
    }

    fn handle_delete(
        &mut self,
        req: &osquery::ExtensionPluginRequest,
    ) -> osquery::ExtensionResponse {
        let row_id = match parse_row_id(req, "id") {
            Ok(id) => id,
            Err(e) => {
                return mutation_response(MutationResult::Failure(format!("delete: {e}")));
            }
        };
        let context = parse_mutation_context(req);

        let request = DeleteRequest { row_id, context };
        dispatch_mutation("delete", self.inner.delete(request))
    }
}

impl<T: WritableTable> OsqueryPlugin for WritableTablePlugin<T> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn registry_name(&self) -> RegistryName {
        RegistryName::Table
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        build_routes(&self.inner.columns())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.inner.name()))
    )]
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        match req.get("action").map(String::as_str) {
            Some("generate") => handle_generate(&req, |ctx| self.inner.generate(ctx)),
            Some("columns") => {
                let ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
                osquery::ExtensionResponse::new(ok, self.routes())
            }
            Some("insert") => self.handle_insert(&req),
            Some("update") => self.handle_update(&req),
            Some("delete") => self.handle_delete(&req),
            Some(action) => error_response(&format!("unknown action: {action}")),
            None => error_response("missing action"),
        }
    }
}

impl<GenFunc: FnMut(QueryContext) -> Result<Table> + Send + Sync> OsqueryPlugin
    for TablePlugin<GenFunc>
{
    fn name(&self) -> &str {
        &self.name
    }

    fn registry_name(&self) -> RegistryName {
        RegistryName::Table
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        build_routes(&self.columns)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self, req), fields(plugin = %self.name))
    )]
    fn call(&mut self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        match req.get("action").map(String::as_str) {
            Some("generate") => handle_generate(&req, |ctx| (self.generate)(ctx)),
            Some("columns") => {
                let ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
                osquery::ExtensionResponse::new(ok, self.routes())
            }
            Some(action) => error_response(&format!("unknown action: {action}")),
            None => error_response("missing action"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_plugin() {
        let status_ok = osquery::ExtensionStatus::new(0, String::from("OK"), None);
        let mut called_query_ctx = QueryContext::default();
        let mut plugin = TablePlugin::new(
            "mock",
            vec![
                ColumnDefinition::text("text"),
                ColumnDefinition::integer("integer"),
                ColumnDefinition::big_int("big_int"),
                ColumnDefinition::double("double"),
            ],
            |qctx| {
                called_query_ctx = qctx;
                Ok(vec![BTreeMap::from([
                    ("text".to_string(), "hello world".to_string()),
                    ("integer".to_string(), "123".to_string()),
                    ("big_int".to_string(), "-1234567890".to_string()),
                    ("double".to_string(), "3.14159".to_string()),
                ])])
            },
        );

        let tresp = vec![
            BTreeMap::from([
                (String::from("id"), String::from("column")),
                (String::from("name"), String::from("text")),
                (String::from("type"), String::from("TEXT")),
                (String::from("op"), String::from("0")),
            ]),
            BTreeMap::from([
                (String::from("id"), String::from("column")),
                (String::from("name"), String::from("integer")),
                (String::from("type"), String::from("INTEGER")),
                (String::from("op"), String::from("0")),
            ]),
            BTreeMap::from([
                (String::from("id"), String::from("column")),
                (String::from("name"), String::from("big_int")),
                (String::from("type"), String::from("BIGINT")),
                (String::from("op"), String::from("0")),
            ]),
            BTreeMap::from([
                (String::from("id"), String::from("column")),
                (String::from("name"), String::from("double")),
                (String::from("type"), String::from("DOUBLE")),
                (String::from("op"), String::from("0")),
            ]),
        ];

        assert_eq!(plugin.name(), "mock");
        assert_eq!(plugin.registry_name(), RegistryName::Table);
        assert_eq!(tresp, plugin.routes());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("columns"),
        )]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert_eq!(tresp, resp.response.unwrap());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("generate")),
            (String::from("context"), String::from("{}")),
        ]));
        assert_eq!(resp.status.unwrap(), status_ok);
        assert_eq!(called_query_ctx.len(), QueryContext::default().len());
        assert_eq!(
            vec![BTreeMap::from([
                (String::from("big_int"), String::from("-1234567890")),
                (String::from("double"), String::from("3.14159")),
                (String::from("integer"), String::from("123")),
                (String::from("text"), String::from("hello world")),
            ]),],
            resp.response.unwrap()
        );
    }

    #[test]
    fn table_plugin_errors() {
        let mut called = 0;
        let mut plugin = TablePlugin::new(
            "mock",
            vec![
                ColumnDefinition::text("text"),
                ColumnDefinition::integer("integer"),
                ColumnDefinition::big_int("big_int"),
                ColumnDefinition::double("double"),
            ],
            |_| {
                called += 1;
                Err("foobar".into())
            },
        );
        assert_eq!(
            1,
            plugin
                .call(osquery::ExtensionPluginRequest::new())
                .status
                .unwrap()
                .code
                .unwrap()
        );
        assert_eq!(
            1,
            plugin
                .call(osquery::ExtensionPluginRequest::from([(
                    String::from("action"),
                    String::from("bad")
                )]))
                .status
                .unwrap()
                .code
                .unwrap()
        );
        // Bad context JSON
        assert_eq!(
            1,
            plugin
                .call(osquery::ExtensionPluginRequest::from([
                    (String::from("action"), String::from("generate")),
                    (String::from("context"), String::from("{[]}"))
                ]))
                .status
                .unwrap()
                .code
                .unwrap()
        );
        // generate returns Err
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("generate")),
            (String::from("context"), String::from("{}")),
        ]));
        assert_eq!(1, resp.status.clone().unwrap().code.unwrap());
        assert_eq!(
            "error generating table: foobar".to_string(),
            resp.status.unwrap().message.unwrap()
        );
        assert_eq!(called, 1, "generate should have been called only once");
    }

    #[test]
    fn generate_with_new_and_unknown_operators() {
        let mut seen_constraints = Vec::new();
        let mut plugin = TablePlugin::new("mock", vec![ColumnDefinition::text("result")], |qctx| {
            seen_constraints = qctx
                .get("result")
                .map(|list| list.constraints().to_vec())
                .unwrap_or_default();
            Ok(vec![BTreeMap::from([(
                "result".to_string(),
                "passed".to_string(),
            )])])
        });

        let context = r#"{"constraints": [
            {
                "name": "result",
                "affinity": "TEXT",
                "list": [
                    {"op": 68, "expr": "pending"},
                    {"op": 73, "expr": "3"},
                    {"op": 9999, "expr": "ignored"}
                ]
            }
        ]}"#;
        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("generate")),
            (String::from("context"), String::from(context)),
        ]));
        assert_eq!(0, resp.status.unwrap().code.unwrap());
        assert_eq!(1, resp.response.unwrap().len());
        assert_eq!(
            vec![
                Constraint {
                    operator: Operator::NotEquals,
                    expression: "pending".to_string(),
                },
                Constraint {
                    operator: Operator::Limit,
                    expression: "3".to_string(),
                },
            ],
            seen_constraints
        );
    }

    #[test]
    fn column_type() {
        let test_cases = vec![
            (ColumnType::BigInt, r#"{ "affinity":"BIGINT" }"#),
            (ColumnType::Double, r#"{  "affinity":"DOUBLE" }"#),
            (ColumnType::Integer, r#"{ "affinity":"INTEGER" }"#),
            (ColumnType::Text, r#"{ "affinity":"TEXT" }"#),
        ];
        for (typ, data) in test_cases {
            let p: BTreeMap<String, ColumnType> = serde_json::from_str(data).unwrap();
            assert_eq!(typ, *p.get("affinity").unwrap());
        }
    }

    #[test]
    fn operator() {
        let test_cases = vec![
            // from int
            (false, Operator::Equals, r#"{ "op": 2 }"#),
            (false, Operator::GreaterThan, r#"{  "op": 4 }"#),
            (false, Operator::LessThanOrEquals, r#"{ "op": 8 }"#),
            (false, Operator::LessThan, r#"{ "op": 16 }"#),
            (false, Operator::GreaterThanOrEquals, r#"{ "op": 32 }"#),
            (false, Operator::Match, r#"{ "op": 64 }"#),
            (false, Operator::Like, r#"{ "op": 65 }"#),
            (false, Operator::Glob, r#"{ "op": 66 }"#),
            (false, Operator::Regexp, r#"{ "op": 67 }"#),
            (false, Operator::Unique, r#"{ "op": 1 }"#),
            (false, Operator::In, r#"{ "op": 3 }"#),
            (false, Operator::NotEquals, r#"{ "op": 68 }"#),
            (false, Operator::IsNot, r#"{ "op": 69 }"#),
            (false, Operator::IsNotNull, r#"{ "op": 70 }"#),
            (false, Operator::IsNull, r#"{ "op": 71 }"#),
            (false, Operator::Is, r#"{ "op": 72 }"#),
            (false, Operator::Limit, r#"{ "op": 73 }"#),
            (false, Operator::Offset, r#"{ "op": 74 }"#),
            (true, Operator::Unique, r#"{ "op": 9999 }"#),
            // from &str
            (false, Operator::Equals, r#"{ "op": "2" }"#),
            (false, Operator::GreaterThan, r#"{  "op": "4" }"#),
            (false, Operator::LessThanOrEquals, r#"{ "op": "8" }"#),
            (false, Operator::LessThan, r#"{ "op": "16" }"#),
            (false, Operator::GreaterThanOrEquals, r#"{ "op": "32" }"#),
            (false, Operator::Match, r#"{ "op": "64" }"#),
            (false, Operator::Like, r#"{ "op": "65" }"#),
            (false, Operator::Glob, r#"{ "op": "66" }"#),
            (false, Operator::Regexp, r#"{ "op": "67" }"#),
            (false, Operator::Unique, r#"{ "op": "1" }"#),
            (false, Operator::NotEquals, r#"{ "op": "68" }"#),
            (false, Operator::Limit, r#"{ "op": "73" }"#),
            (true, Operator::Unique, r#"{ "op": "9999" }"#),
        ];
        for (should_err, typ, data) in test_cases {
            let op: result::Result<BTreeMap<String, Operator>, _> = serde_json::from_str(data);
            match op {
                Ok(p) => {
                    assert!(!should_err);
                    assert_eq!(typ, *p.get("op").unwrap());
                }
                Err(e) => {
                    assert!(
                        e.to_string().contains("invalid operator value: 9999"),
                        "unexpected error: {e}"
                    );
                    assert!(should_err);
                }
            }
        }
        let invalid_op = r#"{ "op": [] }"#;
        let op: result::Result<BTreeMap<String, Operator>, _> = serde_json::from_str(invalid_op);
        op.expect_err("should be invalid operator value");
    }

    #[test]
    fn deserialize_constraint_list() {
        let test_cases = vec![
            (true, r"bad", None),
            (true, r#"{"foo": "bar"}"#, None),
            (false, r#"{"affinity":"BIGINT"}"#, Some(Vec::new())),
            (
                false,
                r#"{"affinity":"BIGINT", "list": "" }"#,
                Some(Vec::new()),
            ),
            (
                false,
                r#"{"affinity":"BIGINT", "list": [{"op":"2","expr":"foo"}] }"#,
                Some(vec![Constraint {
                    operator: Operator::Equals,
                    expression: "foo".to_string(),
                }]),
            ),
            (
                false,
                r#"{"affinity":"TEXT", "list": [{"op":68,"expr":"pending"}] }"#,
                Some(vec![Constraint {
                    operator: Operator::NotEquals,
                    expression: "pending".to_string(),
                }]),
            ),
            (
                false,
                r#"{"affinity":"INTEGER", "list": [{"op":73,"expr":"3"}] }"#,
                Some(vec![Constraint {
                    operator: Operator::Limit,
                    expression: "3".to_string(),
                }]),
            ),
            // unknown operators are skipped, not fatal
            (
                false,
                r#"{"affinity":"TEXT", "list": [{"op":9999,"expr":"x"},{"op":2,"expr":"foo"}] }"#,
                Some(vec![Constraint {
                    operator: Operator::Equals,
                    expression: "foo".to_string(),
                }]),
            ),
        ];
        for (should_err, data, constraints) in test_cases {
            match serde_json::from_str(data) {
                Ok::<ConstraintList, _>(val) => {
                    assert!(!should_err);
                    if let Some(s) = val.constraints.first() {
                        assert_eq!(
                            s.expression,
                            constraints.unwrap().first().unwrap().expression
                        )
                    }
                }
                Err(_) => assert!(should_err),
            }
        }
    }

    #[test]
    fn deserialize_query_context() {
        let test_cases = vec![
            (true, r"bad", None),
            (false, r#"{"foo": "bar"}"#, Some(BTreeMap::new())),
            (
                false,
                r#"
                {"constraints": [
                    {
                        "name":"double",
                        "list":"",
                        "affinity":"DOUBLE"
                      }
                ]}
            "#,
                Some(BTreeMap::from([(
                    "double".to_string(),
                    ConstraintList {
                        affinity: ColumnType::Double,
                        constraints: vec![],
                    },
                )])),
            ),
            (
                false,
                r#"
                {"constraints": [
                    {
                        "name":"big_int",
                        "list":[{"op":"2","expr":"foo"}],
                        "affinity":"BIGINT"
                      }
                ]}
            "#,
                Some(BTreeMap::from([(
                    "big_int".to_string(),
                    ConstraintList {
                        affinity: ColumnType::BigInt,
                        constraints: vec![Constraint {
                            operator: Operator::Equals,
                            expression: "foo".to_string(),
                        }],
                    },
                )])),
            ),
            (
                false,
                r#"
                {"constraints": [
                    {
                        "name":"big_int",
                        "list":"",
                        "affinity":"BIGINT"
                    },
                    {
                        "name":"text",
                        "list":"",
                        "affinity":"TEXT"
                    }
                ]}
            "#,
                Some(BTreeMap::from([
                    (
                        "big_int".to_string(),
                        ConstraintList {
                            affinity: ColumnType::BigInt,
                            constraints: vec![],
                        },
                    ),
                    (
                        "text".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![],
                        },
                    ),
                ])),
            ),
        ];
        for (should_err, data, constraints) in test_cases {
            match serde_json::from_str::<QueryContext>(data) {
                Ok(ctxs) => {
                    assert!(!should_err);
                    let constraints = &constraints.unwrap();
                    for k in constraints.keys() {
                        assert!(ctxs.contains_key(k));
                        assert_eq!(
                            constraints.get(k).unwrap().constraints.len(),
                            ctxs.get(k).unwrap().constraints.len()
                        )
                    }
                }
                Err(_) => assert!(should_err),
            }
        }
    }

    #[test]
    fn column_options_bitmask() {
        // Option bitmask values: Index=1, Required=2, Additional=4, Optimized=8, Hidden=16
        assert_eq!(0, ColumnDefinition::text("c").options());
        assert_eq!(
            1,
            ColumnDefinition::new("c", ColumnType::Text)
                .index()
                .options()
        );
        assert_eq!(
            2,
            ColumnDefinition::new("c", ColumnType::Text)
                .required()
                .options()
        );
        assert_eq!(
            4,
            ColumnDefinition::new("c", ColumnType::Text)
                .additional()
                .options()
        );
        assert_eq!(
            8,
            ColumnDefinition::new("c", ColumnType::Text)
                .optimized()
                .options()
        );
        assert_eq!(
            16,
            ColumnDefinition::new("c", ColumnType::Text)
                .hidden()
                .options()
        );
        // Combined: Index + Hidden = 17
        assert_eq!(
            17,
            ColumnDefinition::new("c", ColumnType::Text)
                .index()
                .hidden()
                .options()
        );
        // All options = 31
        assert_eq!(
            31,
            ColumnDefinition::new("c", ColumnType::Text)
                .index()
                .required()
                .additional()
                .optimized()
                .hidden()
                .options()
        );
    }

    #[test]
    fn column_options_in_routes() {
        let plugin = TablePlugin::new(
            "mock",
            vec![
                ColumnDefinition::new("indexed", ColumnType::Text).index(),
                ColumnDefinition::new("required", ColumnType::Integer)
                    .required()
                    .index(),
                ColumnDefinition::text("plain"),
            ],
            |_| Ok(vec![]),
        );
        let routes = plugin.routes();
        assert_eq!(routes[0].get("op").unwrap(), "1"); // Index
        assert_eq!(routes[1].get("op").unwrap(), "3"); // Required + Index
        assert_eq!(routes[2].get("op").unwrap(), "0"); // no options
    }

    #[test]
    fn column_type_display() {
        assert_eq!("UNKNOWN", ColumnType::Unknown.to_string());
        assert_eq!("TEXT", ColumnType::Text.to_string());
        assert_eq!("INTEGER", ColumnType::Integer.to_string());
        assert_eq!("BIGINT", ColumnType::BigInt.to_string());
        assert_eq!("UNSIGNED BIGINT", ColumnType::UnsignedBigInt.to_string());
        assert_eq!("DOUBLE", ColumnType::Double.to_string());
        assert_eq!("BLOB", ColumnType::Blob.to_string());
    }

    #[test]
    fn column_type_json_serialization() {
        assert_eq!(
            r#""unknown""#,
            serde_json::to_string(&ColumnType::Unknown).unwrap()
        );
        assert_eq!(
            r#""text""#,
            serde_json::to_string(&ColumnType::Text).unwrap()
        );
        assert_eq!(
            r#""unsigned_bigint""#,
            serde_json::to_string(&ColumnType::UnsignedBigInt).unwrap()
        );
        assert_eq!(
            r#""blob""#,
            serde_json::to_string(&ColumnType::Blob).unwrap()
        );
    }

    #[test]
    fn column_description_and_notes() {
        let col = ColumnDefinition::text("c")
            .with_description("A description")
            .with_notes("Some notes");
        assert_eq!(col.description, "A description");
        assert_eq!(col.notes, "Some notes");
    }

    #[test]
    fn table_spec_generation() {
        let plugin = TablePlugin::new(
            "test_table",
            vec![
                ColumnDefinition::new("id", ColumnType::Integer).index(),
                ColumnDefinition::text("name").with_description("The name"),
            ],
            |_| Ok(vec![]),
        )
        .description("A test table")
        .url("https://example.com")
        .example("SELECT * FROM test_table")
        .platforms(vec![Platform::Darwin, Platform::Linux]);
        let spec = plugin.spec();
        assert_eq!(spec.name, "test_table");
        assert_eq!(spec.description, "A test table");
        assert_eq!(spec.url, "https://example.com");
        assert_eq!(spec.platforms, vec![Platform::Darwin, Platform::Linux]);
        assert_eq!(spec.examples, vec!["SELECT * FROM test_table"]);
        assert_eq!(spec.columns.len(), 2);
        assert!(!spec.evented);
        assert!(!spec.cacheable);

        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains(r#""name":"test_table""#));
        assert!(json.contains(r#""platforms":["darwin","linux"]"#));
    }

    #[test]
    fn table_spec_default_platform() {
        let plugin = TablePlugin::new("default_platform", vec![], |_| Ok(vec![]));
        let spec = plugin.spec();
        // Should have auto-detected platform
        assert!(!spec.platforms.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deserialize_varying_query_contexts() {
        let test_cases = vec![
            // Stringy JSON from osquery version < 3
            (
                false,
                r#"{"constraints":[{"name":"domain","list":[{"op":"2","expr":"osquery_rs.co"}],"affinity":"TEXT"},{"name":"email","list":"","affinity":"TEXT"}]}"#,
                Some(BTreeMap::from([
                    (
                        "domain".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Equals,
                                expression: "osquery_rs.co".to_string(),
                            }],
                        },
                    ),
                    (
                        "email".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![],
                        },
                    ),
                ])),
            ),
            // Strongly typed JSON from osquery version > 3
            (
                false,
                r#"{"constraints":[{"name":"domain","list":[{"op":2,"expr":"osquery_rs.co"}],"affinity":"TEXT"},{"name":"email","list":[],"affinity":"TEXT"}]}"#,
                Some(BTreeMap::from([
                    (
                        "domain".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Equals,
                                expression: "osquery_rs.co".to_string(),
                            }],
                        },
                    ),
                    (
                        "email".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![],
                        },
                    ),
                ])),
            ),
            // Stringy (osquery < v3)
            (
                false,
                r#"{"constraints":[{"name":"path","list":[{"op":"65","expr":"%foobar"}],"affinity":"TEXT"},{"name":"query","list":[{"op":"2","expr":"kMDItemFSName = \"google*\""}],"affinity":"TEXT"}]}"#,
                Some(BTreeMap::from([
                    (
                        "path".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Like,
                                expression: "%foobar".to_string(),
                            }],
                        },
                    ),
                    (
                        "query".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Equals,
                                expression: "kMDItemFSName = \"google*\"".to_string(),
                            }],
                        },
                    ),
                ])),
            ),
            // Strong (osquery >= v3)
            (
                false,
                r#"{"constraints":[{"name":"path","list":[{"op":65,"expr":"%foobar"}],"affinity":"TEXT"},{"name":"query","list":[{"op":2,"expr":"kMDItemFSName = \"google*\""}],"affinity":"TEXT"}]}"#,
                Some(BTreeMap::from([
                    (
                        "path".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Like,
                                expression: "%foobar".to_string(),
                            }],
                        },
                    ),
                    (
                        "query".to_string(),
                        ConstraintList {
                            affinity: ColumnType::Text,
                            constraints: vec![Constraint {
                                operator: Operator::Equals,
                                expression: "kMDItemFSName = \"google*\"".to_string(),
                            }],
                        },
                    ),
                ])),
            ),
            // Error cases
            (true, r"{bad json}", None),
            (
                true,
                r#"{"constraints":[{"name":"foo","list":["bar", "baz"],"affinity":"TEXT"}]"#,
                None,
            ),
        ];
        for (should_err, data, constraints) in test_cases {
            match serde_json::from_str::<QueryContext>(data) {
                Ok(ctxs) => {
                    assert!(!should_err);
                    let constraints = &constraints.unwrap();
                    for k in constraints.keys() {
                        assert!(ctxs.contains_key(k));
                        assert_eq!(
                            constraints.get(k).unwrap().constraints.len(),
                            ctxs.get(k).unwrap().constraints.len()
                        );
                        match ctxs.get(k).unwrap().constraints.first() {
                            Some(cnt) => {
                                assert_eq!(
                                    cnt.expression,
                                    ctxs.get(k).unwrap().constraints.first().unwrap().expression
                                );
                                assert_eq!(
                                    cnt.operator,
                                    ctxs.get(k).unwrap().constraints.first().unwrap().operator
                                );
                            }
                            None => {
                                assert!(constraints.get(k).unwrap().constraints.is_empty())
                            }
                        }
                    }
                }
                Err(_) => assert!(should_err),
            }
        }
    }

    // ── Writable table tests ──────────────────────────────────────────

    #[test]
    fn parse_json_value_array_basic() {
        let vals = parse_json_value_array(r#"["hello", null, "42"]"#).unwrap();
        assert_eq!(
            vals,
            vec![Some("hello".to_string()), None, Some("42".to_string()),]
        );
    }

    #[test]
    fn parse_json_value_array_empty() {
        let vals = parse_json_value_array("[]").unwrap();
        assert!(vals.is_empty());
    }

    #[test]
    fn parse_json_value_array_numeric_values() {
        let vals = parse_json_value_array(r"[123, 3.14, true]").unwrap();
        assert_eq!(
            vals,
            vec![
                Some("123".to_string()),
                Some("3.14".to_string()),
                Some("true".to_string()),
            ]
        );
    }

    #[test]
    fn parse_json_value_array_invalid() {
        assert!(parse_json_value_array("not json").is_err());
        assert!(parse_json_value_array(r#"{"key": "val"}"#).is_err());
    }

    #[test]
    fn mutation_response_success() {
        let resp = mutation_response(MutationResult::Success { row_id: Some(42) });
        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
        assert_eq!(row.get("id").unwrap(), "42");
    }

    #[test]
    fn mutation_response_success_no_rowid() {
        let resp = mutation_response(MutationResult::Success { row_id: None });
        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
        assert!(row.get("id").is_none());
    }

    #[test]
    fn mutation_response_readonly() {
        let resp = mutation_response(MutationResult::ReadOnly);
        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "readonly");
    }

    #[test]
    fn mutation_response_failure() {
        let resp = mutation_response(MutationResult::Failure("bad data".to_string()));
        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert_eq!(row.get("message").unwrap(), "bad data");
    }

    #[test]
    fn mutation_response_constraint() {
        let resp = mutation_response(MutationResult::Constraint);
        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "constraint");
    }

    struct MockWritableTable {
        data: BTreeMap<i64, (String, String)>,
    }

    impl MockWritableTable {
        fn new() -> Self {
            Self {
                data: BTreeMap::new(),
            }
        }
    }

    impl WritableTable for MockWritableTable {
        fn name(&self) -> &'static str {
            "mock_writable"
        }

        fn columns(&self) -> Vec<ColumnDefinition> {
            vec![
                ColumnDefinition::text("key"),
                ColumnDefinition::text("value"),
            ]
        }

        fn generate(&mut self, _ctx: QueryContext) -> crate::Result<Table> {
            Ok(self
                .data
                .values()
                .map(|(k, v)| {
                    BTreeMap::from([
                        ("key".to_string(), k.clone()),
                        ("value".to_string(), v.clone()),
                    ])
                })
                .collect())
        }

        fn insert(&mut self, req: InsertRequest) -> crate::Result<MutationResult> {
            let key = req
                .values
                .first()
                .and_then(Clone::clone)
                .unwrap_or_default();
            let value = req.values.get(1).and_then(Clone::clone).unwrap_or_default();
            let row_id = req.row_id.unwrap_or(0);
            self.data.insert(row_id, (key, value));
            Ok(MutationResult::Success {
                row_id: Some(row_id),
            })
        }

        fn update(&mut self, req: UpdateRequest) -> crate::Result<MutationResult> {
            let key = req
                .values
                .first()
                .and_then(Clone::clone)
                .unwrap_or_default();
            let value = req.values.get(1).and_then(Clone::clone).unwrap_or_default();
            let id = req.new_row_id.unwrap_or(req.row_id);
            self.data.remove(&req.row_id);
            self.data.insert(id, (key, value));
            Ok(MutationResult::Success { row_id: None })
        }

        fn delete(&mut self, req: DeleteRequest) -> crate::Result<MutationResult> {
            self.data.remove(&req.row_id);
            Ok(MutationResult::Success { row_id: None })
        }
    }

    #[test]
    fn writable_table_insert() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("insert")),
            (
                String::from("json_value_array"),
                String::from(r#"["k1","v1"]"#),
            ),
            (String::from("auto_rowid"), String::from("true")),
            (String::from("id"), String::from("1")),
            (String::from("context"), String::from("{}")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
        assert_eq!(row.get("id").unwrap(), "1");
    }

    #[test]
    fn writable_table_update() {
        let mut table = MockWritableTable::new();
        table.data.insert(5, ("k1".into(), "v1".into()));
        let mut plugin = WritableTablePlugin::new(table);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("update")),
            (String::from("id"), String::from("5")),
            (String::from("new_id"), String::from("10")),
            (
                String::from("json_value_array"),
                String::from(r#"["k2","v2"]"#),
            ),
            (String::from("context"), String::from("{}")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
    }

    #[test]
    fn writable_table_delete() {
        let mut table = MockWritableTable::new();
        table.data.insert(42, ("k1".into(), "v1".into()));
        let mut plugin = WritableTablePlugin::new(table);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("delete")),
            (String::from("id"), String::from("42")),
            (String::from("context"), String::from("{}")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
    }

    #[test]
    fn writable_table_generate() {
        let mut table = MockWritableTable::new();
        table.data.insert(1, ("greeting".into(), "hello".into()));
        let mut plugin = WritableTablePlugin::new(table);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("generate")),
            (String::from("context"), String::from("{}")),
        ]));
        assert_eq!(resp.status.unwrap().code.unwrap(), 0);
        let rows = resp.response.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("key").unwrap(), "greeting");
    }

    #[test]
    fn writable_table_delete_missing_id() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("delete"),
        )]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(row.get("message").unwrap().contains("missing id"));
    }

    #[test]
    fn writable_table_update_missing_id() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("update")),
            (String::from("json_value_array"), String::from("[]")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(row.get("message").unwrap().contains("missing id"));
    }

    #[test]
    fn writable_table_insert_missing_values() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([(
            String::from("action"),
            String::from("insert"),
        )]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(
            row.get("message")
                .unwrap()
                .contains("missing json_value_array")
        );
    }

    #[test]
    fn writable_table_insert_invalid_json() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("insert")),
            (String::from("json_value_array"), String::from("not json")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(
            row.get("message")
                .unwrap()
                .contains("invalid json_value_array")
        );
    }

    #[test]
    fn writable_table_update_invalid_id() {
        let mut plugin = WritableTablePlugin::new(MockWritableTable::new());

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("update")),
            (String::from("id"), String::from("not_a_number")),
            (String::from("json_value_array"), String::from("[]")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(row.get("message").unwrap().contains("invalid id"));
    }

    #[test]
    fn writable_table_with_context() {
        struct ContextChecker;
        impl WritableTable for ContextChecker {
            fn name(&self) -> &'static str {
                "ctx_check"
            }
            fn columns(&self) -> Vec<ColumnDefinition> {
                vec![]
            }
            fn generate(&mut self, _ctx: QueryContext) -> crate::Result<Table> {
                Ok(vec![])
            }
            fn insert(&mut self, _req: InsertRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
            fn update(&mut self, _req: UpdateRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
            fn delete(&mut self, req: DeleteRequest) -> crate::Result<MutationResult> {
                assert!(!req.context.is_empty());
                assert!(req.context.contains_key("name"));
                Ok(MutationResult::Success { row_id: None })
            }
        }

        let mut plugin = WritableTablePlugin::new(ContextChecker);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("delete")),
            (String::from("id"), String::from("1")),
            (
                String::from("context"),
                String::from(r#"{"constraints":[{"name":"name","list":"","affinity":"TEXT"}]}"#),
            ),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "success");
    }

    #[test]
    fn writable_table_callback_returns_constraint() {
        struct ConstraintTable;
        impl WritableTable for ConstraintTable {
            fn name(&self) -> &'static str {
                "constraint_tbl"
            }
            fn columns(&self) -> Vec<ColumnDefinition> {
                vec![]
            }
            fn generate(&mut self, _ctx: QueryContext) -> crate::Result<Table> {
                Ok(vec![])
            }
            fn insert(&mut self, _req: InsertRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Constraint)
            }
            fn update(&mut self, _req: UpdateRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
            fn delete(&mut self, _req: DeleteRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
        }

        let mut plugin = WritableTablePlugin::new(ConstraintTable);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("insert")),
            (String::from("json_value_array"), String::from("[]")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "constraint");
    }

    #[test]
    fn writable_table_callback_returns_err() {
        struct ErrTable;
        impl WritableTable for ErrTable {
            fn name(&self) -> &'static str {
                "err_tbl"
            }
            fn columns(&self) -> Vec<ColumnDefinition> {
                vec![]
            }
            fn generate(&mut self, _ctx: QueryContext) -> crate::Result<Table> {
                Ok(vec![])
            }
            fn insert(&mut self, _req: InsertRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
            fn update(&mut self, _req: UpdateRequest) -> crate::Result<MutationResult> {
                Ok(MutationResult::Success { row_id: None })
            }
            fn delete(&mut self, _req: DeleteRequest) -> crate::Result<MutationResult> {
                Err("storage unavailable".into())
            }
        }

        let mut plugin = WritableTablePlugin::new(ErrTable);

        let resp = plugin.call(osquery::ExtensionPluginRequest::from([
            (String::from("action"), String::from("delete")),
            (String::from("id"), String::from("1")),
        ]));

        let row = &resp.response.unwrap()[0];
        assert_eq!(row.get("status").unwrap(), "failure");
        assert!(row.get("message").unwrap().contains("storage unavailable"));
    }

    #[test]
    fn writable_table_routes() {
        let plugin = WritableTablePlugin::new(MockWritableTable::new());
        let routes = plugin.routes();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].get("name").unwrap(), "key");
        assert_eq!(routes[1].get("name").unwrap(), "value");
    }
}
