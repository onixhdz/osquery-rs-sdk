#![cfg(windows)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::{Error, ErrorKind},
    ops::Add,
    os::windows::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use winapi::{shared::winerror, um::winbase};

pub struct NamedPipeClient {
    file: File,
    /// Shared with every [`try_clone`](Self::try_clone) so that
    /// [`close`](Self::close) takes effect across all handles. Dropping one
    /// duplicated pipe handle does not end the connection (unlike a Unix
    /// socket `shutdown`), so closure is tracked explicitly.
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
            file,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn try_clone(&self) -> io::Result<NamedPipeClient> {
        Ok(NamedPipeClient {
            file: self.file.try_clone()?,
            closed: Arc::clone(&self.closed),
        })
    }

    /// Mark the connection closed. Subsequent reads and writes on this
    /// handle and every clone fail with [`ErrorKind::NotConnected`].
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
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
        self.file.read(buf)
    }
}

impl std::io::Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_open()?;
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_open()?;
        self.file.flush()
    }
}
