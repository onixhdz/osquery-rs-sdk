//! Rust bindings for creating `osquery` extensions in Rust.
//!
//! This crate implements the components required to build a working
//! osquery plugin server and client.

// Panic/print allowances for test code live in clippy.toml
// (allow-unwrap-in-tests etc.); these pedantic lints have no test toggle.
#![cfg_attr(
    test,
    allow(
        clippy::unnecessary_wraps,
        clippy::semicolon_if_nothing_returned,
        clippy::needless_pass_by_value,
    )
)]

use std::result;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    unsafe_code,
    unused
)]
mod osquery; // Auto-generated bindings from Thrift.

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "server")]
mod server;

#[cfg(feature = "plugins")]
pub mod plugin;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "client")]
pub use crate::client::{ExtensionManager, ExtensionManagerClient};

#[cfg(feature = "server")]
pub use crate::server::{
    ExtensionManagerServer, ExtensionManagerServerBuilder, OsqueryPlugin, RegistryName,
    ShutdownHandle,
};

#[cfg(feature = "plugins")]
pub use crate::plugin::{
    ColumnDefinition, ColumnType, ColumnValues, ConfigPlugin, Constraint, ConstraintList,
    DeleteRequest, DistributedPlugin, InsertRequest, InvalidOperator, LogType, LoggerPlugin,
    MutationResult, Operator, QueriesRequest, QueryContext, QueryResponse, Stats, Table,
    TablePlugin, UpdateRequest, WritableTable, WritableTablePlugin,
};

/// Result type used throughout the plugin APIs.
pub type Result<T> = result::Result<T, Error>;

/// Error type returned by all the plugins.
///
/// This is a typed error enum that supports context chaining via the
/// [`context`](Error::context) method, as well as automatic conversion
/// from Thrift and I/O errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A Thrift transport, protocol, or application error.
    ///
    /// The message is extracted and formatted because the upstream thrift
    /// crate's `Display` impl for `ApplicationError` discards the user
    /// message and only prints the error kind label.
    #[error("{0}")]
    Transport(String),

    /// An I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// An error with an additional context message wrapping an inner error.
    #[error("{message} - {source}")]
    Context {
        /// The context message describing what operation failed.
        message: String,
        /// The underlying error that caused the failure.
        #[source]
        source: Box<Error>,
    },

    /// A general error with a descriptive message.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Adds context to this error, wrapping it with an additional message.
    ///
    /// If called on an error, the original error becomes the
    /// [`source`](std::error::Error::source) of the returned error.
    #[must_use]
    pub fn context(self, message: &str) -> Self {
        Self::Context {
            message: message.to_string(),
            source: Box::new(self),
        }
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<thrift::Error> for Error {
    fn from(err: thrift::Error) -> Self {
        // The upstream thrift crate's Display impls discard user messages
        // (e.g., ApplicationError only prints "service error" regardless of
        // the message field). We extract and format explicitly.
        let formatted = match err {
            thrift::Error::Transport(ref src) => {
                format!("{}: TransportKind({:?})", src.message, src.kind)
            }
            thrift::Error::Protocol(ref src) => {
                format!("{}: ProtocolKind({:?})", src.message, src.kind)
            }
            thrift::Error::Application(ref src) => {
                format!("{}: ApplicationKind({:?})", src.message, src.kind)
            }
            thrift::Error::User(ref src) => src.to_string(),
        };
        Error::Transport(formatted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_from_thrift() {
        let err = Error::from(thrift::Error::from("test"));
        assert_eq!("test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_from_str() {
        let err = Error::from("test");
        assert_eq!("test", err.to_string());
        let err = Error::from(String::from("test1"));
        assert_eq!("test1", err.to_string());
    }

    #[test]
    fn error_with_msg() {
        let terr = thrift::Error::from("test");
        let err = Error::from(terr).context("hello");
        assert_eq!("hello - test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_msg_into() {
        let err: Error = "test".into();
        assert_eq!("test", err.to_string());
        let err: Error = String::from("hello").into();
        assert_eq!("hello", err.to_string());
        let err: Error = thrift::Error::from("test").into();
        assert_eq!("test: ApplicationKind(Unknown)", err.to_string());
    }

    #[test]
    fn error_msg_fmt() {
        let err: Error = "testing".into();
        assert_eq!(err.to_string(), "testing");
        let err: Error = thrift::Error::from("thrift err msg").into();
        assert_eq!(err.to_string(), "thrift err msg: ApplicationKind(Unknown)");
        let err: Error = thrift::Error::Transport(thrift::TransportError::new(
            thrift::TransportErrorKind::AlreadyOpen,
            "hello transport",
        ))
        .into();
        assert_eq!(
            err.to_string(),
            "hello transport: TransportKind(AlreadyOpen)"
        );
        let err: Error = thrift::Error::from("thrift err msg").into();
        assert_eq!(
            err.context("error from thrift with message").to_string(),
            "error from thrift with message - thrift err msg: ApplicationKind(Unknown)"
        );
        assert_eq!(
            Error::from("initial msg test")
                .context("hello test")
                .to_string(),
            "hello test - initial msg test"
        );
        assert_eq!(
            Error::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
                .context("hello io")
                .to_string(),
            "hello io - broken pipe"
        );
    }

    #[test]
    fn error_source_chain() {
        let inner: Error = "inner error".into();
        let outer = inner.context("outer context");
        // std::error::Error::source() should return the inner error
        let source = std::error::Error::source(&outer);
        assert!(source.is_some(), "source should be Some");
        assert!(
            source
                .expect("source should be Some")
                .to_string()
                .contains("inner error"),
        );
    }
}
