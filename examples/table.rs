#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps
)]

use osquery_rs_sdk::{
    ColumnDefinition, ExtensionManagerClient, ExtensionManagerServer, QueryContext, Result, Table,
    TablePlugin,
};
use std::{collections::BTreeMap, io::stdin, time::Duration};

#[cfg(unix)]
const OSQUERY_SOCKET: &str = "/var/osquery/osquery.em";
#[cfg(windows)]
const OSQUERY_SOCKET: &str = r"\\.\pipe\osquery.em";

fn example_extension() -> Result<()> {
    let mut server = ExtensionManagerServer::new("example_table_ext", OSQUERY_SOCKET)?;
    server.register_plugin(TablePlugin::new(
        "example_table",
        example_columns(),
        example_generate,
    ))?;
    server.run()
}

fn main() -> Result<()> {
    // start server
    let handle = std::thread::spawn(example_extension);
    std::thread::sleep(Duration::from_secs(2));

    // create a simple client interface
    let mut client = ExtensionManagerClient::connect_with_path(OSQUERY_SOCKET)?;
    println!("##### Enter SQL query for osqueryd ####");
    println!(
        "##### Note: This is a simple interface for osqueryd please use osqueryi instead ####"
    );
    println!("### Example: SELECT * from example_table ###");
    let mut query = String::new();
    while stdin().read_line(&mut query).is_ok() {
        if handle.is_finished() {
            break;
        }
        if let Some('\n' | '\r') = query.chars().next_back() {
            if query.len() > 1 {
                println!("{:?}", client.query(&query)?);
            }
            query.clear();
        }
    }

    handle.join().unwrap()
}

fn example_columns() -> Vec<ColumnDefinition> {
    vec![
        ColumnDefinition::text("hello"),
        ColumnDefinition::integer("integer"),
        ColumnDefinition::big_int("big_int"),
        ColumnDefinition::double("double"),
    ]
}

fn example_generate(qctx: QueryContext) -> Result<Table> {
    println!("{qctx:?}");
    Ok(vec![BTreeMap::from([
        ("hello".to_string(), "hello world".to_string()),
        ("integer".to_string(), "123".to_string()),
        ("big_int".to_string(), "-1234567890".to_string()),
        ("double".to_string(), "3.14159".to_string()),
    ])])
}
