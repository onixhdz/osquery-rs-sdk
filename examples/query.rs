#![allow(clippy::print_stdout)]

fn main() -> osquery_rs_sdk::Result<()> {
    let mut client = osquery_rs_sdk::ExtensionManagerClient::connect()?;
    let rows = client.query("SELECT * FROM users LIMIT 1")?;
    println!("Got results: {rows:?}");
    Ok(())
}
