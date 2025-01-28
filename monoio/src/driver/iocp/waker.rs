//! Custom thread waker based on eventfd.

use std::os::windows::prelude::{AsRawHandle, RawHandle};
use crate::driver::unpark::Unpark;

pub(crate) struct EventWaker {
    // RawFd
    raw: RawHandle,
    // File hold the ownership of fd, only useful when drop
    _file: std::fs::File,
    // Atomic awake status
    pub(crate) awake: std::sync::atomic::AtomicBool,
}

impl EventWaker {
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self {
            raw: file.as_raw_handle(),
            _file: file,
            awake: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub(crate) fn wake(&self) -> std::io::Result<()> {
        // Skip wake if already awake
        if self.awake.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        // Write data into EventFd to wake the executor.
        let buf = 0x1u64.to_ne_bytes();
        unsafe {
            // SAFETY: Writing number to eventfd is thread safe.
            libc::write(self.raw, buf.as_ptr().cast(), buf.len());
            Ok(())
        }
    }
}

impl AsRawHandle for EventWaker {
    fn as_raw_handle(&self) -> RawHandle {
        self.raw
    }
}

#[derive(Clone)]
pub struct UnparkHandle(pub(crate) std::sync::Weak<EventWaker>);

impl Unpark for UnparkHandle {
    fn unpark(&self) -> std::io::Result<()> {
        if let Some(w) = self.0.upgrade() {
            w.wake()
        } else {
            Ok(())
        }
    }
}
