#![cfg(windows)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::{Error, ErrorKind},
    ops::Add,
    os::windows::fs::OpenOptionsExt,
    os::windows::io::AsRawHandle,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use winapi::{shared::winerror, um::ioapiset, um::winbase};

pub struct NamedPipeClient {
    /// Shared (not duplicated) across every [`try_clone`](Self::try_clone)
    /// so the `CancelIoEx` in [`close`](Self::close) reaches the one handle
    /// all clones use for I/O. `CancelIoEx` only cancels operations issued
    /// on the given handle, so duplicated handles would not be woken.
    file: Arc<File>,
    /// Shared with every clone so that [`close`](Self::close) takes effect
    /// across all of them. Dropping one clone does not end the connection
    /// (unlike a Unix socket `shutdown`), so closure is tracked explicitly.
    closed: Arc<AtomicBool>,
}

impl NamedPipeClient {
    /// Connect to a named pipe by path.
    ///
    /// Times out if the connection takes longer than a default timeout of 2 seconds.
    /// (We do not use `WaitNamedPipe`.)
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<NamedPipeClient> {
        let mut rw = OpenOptions::new();
        rw.read(true).write(true).custom_flags(
            winbase::SECURITY_IDENTIFICATION
                | winbase::SECURITY_SQOS_PRESENT
                | winbase::FILE_FLAG_OVERLAPPED,
        );

        let timeout = Instant::now().add(Duration::from_secs(2));
        let file = loop {
            // wait for connection timeout
            match timeout.checked_duration_since(Instant::now()) {
                Some(_) => match rw.open(path.as_ref()) {
                    Ok(f) => break f,
                    Err(ref e)
                        if e.raw_os_error() == i32::try_from(winerror::ERROR_PIPE_BUSY).ok() =>
                    {
                        // Wait 10 msec and try again. This is a rather simplistic
                        // view, as we always try each 10 milliseconds.
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(e),
                },
                None => return Err(Error::from(ErrorKind::TimedOut)),
            }
        };
        Ok(NamedPipeClient {
            file: Arc::new(file),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    // Infallible since clones share the handle, but the `Result` keeps
    // signature parity with `UnixStream::try_clone` for shared call sites.
    #[allow(clippy::unnecessary_wraps)]
    pub fn try_clone(&self) -> io::Result<NamedPipeClient> {
        Ok(NamedPipeClient {
            file: Arc::clone(&self.file),
            closed: Arc::clone(&self.closed),
        })
    }

    /// Mark the connection closed and cancel in-flight blocking I/O,
    /// matching Unix `shutdown(Both)` behavior: a thread blocked in a read
    /// or write on any clone is woken with a cancellation error, and
    /// subsequent operations fail with [`ErrorKind::NotConnected`].
    ///
    /// Best-effort: an operation that passes the closed check concurrently
    /// with `close()` but has not yet entered the OS call can still block
    /// until the peer writes or disconnects.
    #[allow(unsafe_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // SAFETY: `self.file` keeps the handle valid for the duration of
        // the call. `CancelIoEx` with a null OVERLAPPED cancels all pending
        // I/O issued on this handle from any thread and does not invalidate
        // the handle.
        unsafe {
            ioapiset::CancelIoEx(self.file.as_raw_handle().cast(), std::ptr::null_mut());
        }
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorKind::NotConnected, "pipe closed"));
        }
        Ok(())
    }
}

impl std::io::Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_open()?;
        (&*self.file).read(buf)
    }
}

impl std::io::Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_open()?;
        (&*self.file).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_open()?;
        (&*self.file).flush()
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::sync::mpsc;

    /// Unix parity: `shutdown(Both)` wakes a thread blocked in `read`.
    /// `close()` must do the same for named pipes, not only fail
    /// subsequent operations.
    #[test]
    fn close_unblocks_inflight_read() {
        const PIPE: &str = r"\\.\pipe\osquery_rs_sdk.named_pipe.close_unblocks.test";
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Hold a silent server end alive so the client read blocks
        // indefinitely instead of failing fast.
        let server = rt.block_on(async {
            tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create(PIPE)
                .unwrap()
        });

        let client = NamedPipeClient::connect(PIPE).unwrap();
        let mut reader = client.try_clone().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            done_tx.send(reader.read(&mut buf)).ok();
        });

        // Give the reader thread time to enter the blocking read.
        std::thread::sleep(Duration::from_millis(200));
        client.close();

        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("close() must unblock an in-flight read");
        assert!(
            result.is_err(),
            "unblocked read should report an error, got {result:?}"
        );
        drop(server);
    }
}
