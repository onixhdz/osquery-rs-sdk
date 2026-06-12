#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::needless_pass_by_value
)]

//! Criterion benchmarks for JSON deserialization hot paths.
//!
//! These benchmarks measure the performance of `QueryContext` and
//! `ConstraintList` deserialization, which are called on every table
//! query from osquery.
//!
//! Run with:
//! ```sh
//! cargo bench --bench deserialization
//! ```

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use osquery_rs_sdk::{ConstraintList, QueryContext};

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// Empty context — baseline overhead.
const CTX_EMPTY: &str = r"{}";

/// Single column, empty constraint list (stringy empty string from osquery < v3).
const CTX_SINGLE_EMPTY: &str = r#"{"constraints":[{"name":"domain","list":"","affinity":"TEXT"}]}"#;

/// Two columns, one with a constraint, one empty (osquery < v3, stringy ops).
const CTX_TWO_COL_STRINGY: &str = r#"{"constraints":[{"name":"domain","list":[{"op":"2","expr":"osquery_rs.co"}],"affinity":"TEXT"},{"name":"email","list":"","affinity":"TEXT"}]}"#;

/// Two columns, one with a constraint, one empty (osquery >= v3, integer ops).
const CTX_TWO_COL_STRONG: &str = r#"{"constraints":[{"name":"domain","list":[{"op":2,"expr":"osquery_rs.co"}],"affinity":"TEXT"},{"name":"email","list":[],"affinity":"TEXT"}]}"#;

/// Complex: two columns with LIKE and Equals operators (stringy).
const CTX_COMPLEX_STRINGY: &str = r#"{"constraints":[{"name":"path","list":[{"op":"65","expr":"%foobar"}],"affinity":"TEXT"},{"name":"query","list":[{"op":"2","expr":"kMDItemFSName = \"google*\""}],"affinity":"TEXT"}]}"#;

/// Complex: two columns with LIKE and Equals operators (strong).
const CTX_COMPLEX_STRONG: &str = r#"{"constraints":[{"name":"path","list":[{"op":65,"expr":"%foobar"}],"affinity":"TEXT"},{"name":"query","list":[{"op":2,"expr":"kMDItemFSName = \"google*\""}],"affinity":"TEXT"}]}"#;

/// Many columns — stress test with 10 columns, each having 3 constraints.
fn ctx_many_columns() -> String {
    let mut constraints = Vec::new();
    for i in 0..10 {
        constraints.push(format!(
            r#"{{"name":"col_{i}","list":[{{"op":2,"expr":"val_a_{i}"}},{{"op":4,"expr":"val_b_{i}"}},{{"op":8,"expr":"val_c_{i}"}}],"affinity":"TEXT"}}"#,
        ));
    }
    format!(r#"{{"constraints":[{}]}}"#, constraints.join(","))
}

// ---------------------------------------------------------------------------
// ConstraintList payloads
// ---------------------------------------------------------------------------

/// Empty constraint list (stringy "").
const CL_EMPTY_STRINGY: &str = r#"{"list":"","affinity":"TEXT"}"#;

/// Empty constraint list (strong []).
const CL_EMPTY_STRONG: &str = r#"{"list":[],"affinity":"BIGINT"}"#;

/// Single constraint (stringy op).
const CL_SINGLE_STRINGY: &str = r#"{"list":[{"op":"2","expr":"foo"}],"affinity":"TEXT"}"#;

/// Single constraint (strong op).
const CL_SINGLE_STRONG: &str = r#"{"list":[{"op":2,"expr":"foo"}],"affinity":"TEXT"}"#;

/// Multiple constraints.
const CL_MULTIPLE: &str = r#"{"list":[{"op":2,"expr":"a"},{"op":4,"expr":"b"},{"op":8,"expr":"c"},{"op":16,"expr":"d"},{"op":65,"expr":"%pattern"}],"affinity":"TEXT"}"#;

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_query_context(c: &mut Criterion) {
    let many = ctx_many_columns();

    let cases: &[(&str, &str)] = &[
        ("empty", CTX_EMPTY),
        ("single_empty", CTX_SINGLE_EMPTY),
        ("two_col_stringy", CTX_TWO_COL_STRINGY),
        ("two_col_strong", CTX_TWO_COL_STRONG),
        ("complex_stringy", CTX_COMPLEX_STRINGY),
        ("complex_strong", CTX_COMPLEX_STRONG),
        ("many_columns_30c", &many),
    ];

    let mut group = c.benchmark_group("query_context_deser");
    for (name, json) in cases {
        // Verify the payload is valid before benchmarking.
        serde_json::from_str::<QueryContext>(json)
            .unwrap_or_else(|e| panic!("invalid test payload '{name}': {e}"));

        group.bench_with_input(BenchmarkId::new("from_str", name), json, |b, json| {
            b.iter(|| serde_json::from_str::<QueryContext>(black_box(json)).unwrap());
        });
    }
    group.finish();
}

fn bench_constraint_list(c: &mut Criterion) {
    let cases: &[(&str, &str)] = &[
        ("empty_stringy", CL_EMPTY_STRINGY),
        ("empty_strong", CL_EMPTY_STRONG),
        ("single_stringy", CL_SINGLE_STRINGY),
        ("single_strong", CL_SINGLE_STRONG),
        ("multiple_5", CL_MULTIPLE),
    ];

    let mut group = c.benchmark_group("constraint_list_deser");
    for (name, json) in cases {
        serde_json::from_str::<ConstraintList>(json)
            .unwrap_or_else(|e| panic!("invalid test payload '{name}': {e}"));

        group.bench_with_input(BenchmarkId::new("from_str", name), json, |b, json| {
            b.iter(|| serde_json::from_str::<ConstraintList>(black_box(json)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_query_context, bench_constraint_list);
criterion_main!(benches);
