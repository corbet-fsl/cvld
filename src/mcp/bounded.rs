//! Byte bounds around the maintained SDK, without parsing JSON-RPC ourselves.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

pub(super) const ORDINARY_ARGUMENT_BYTES: usize = 256 * 1024;
pub(super) const ACCOUNT_ARGUMENT_BYTES: usize = 16 * 1024 * 1024;
// The arguments retain their separate action limit. This allowance covers only
// the actual JSON-RPC envelope and physical delimiter, not a larger account.
pub(super) const FRAME_BYTES: usize = ACCOUNT_ARGUMENT_BYTES + 64 * 1024;

pub(super) struct BoundedRead<R> {
    inner: R,
    maximum: usize,
    current: usize,
    failed: bool,
}
impl<R> BoundedRead<R> {
    pub(super) fn new(inner: R, maximum: usize) -> Self {
        Self {
            inner,
            maximum,
            current: 0,
            failed: maximum == 0,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for BoundedRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP frame exceeds its byte limit",
            )));
        }
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut bytes = [0u8; 8192];
        let size = destination.remaining().min(bytes.len());
        let mut buffer = ReadBuf::new(&mut bytes[..size]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.failed = true;
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) => {}
        }
        for byte in buffer.filled() {
            // State remains attached to the reader across cancelled receive
            // futures and split reads. Every physical newline starts one frame.
            this.current = match this.current.checked_add(1) {
                Some(current) if current <= this.maximum => current,
                _ => {
                    this.failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP frame exceeds its byte limit",
                    )));
                }
            };
            if *byte == b'\n' {
                this.current = 0;
            }
        }
        destination.put_slice(buffer.filled());
        Poll::Ready(Ok(()))
    }
}

struct Count {
    used: usize,
    maximum: usize,
}
impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "MCP arguments exceed their byte limit",
                )
            })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn arguments_fit(name: &str, value: &serde_json::Value) -> crate::error::Result<()> {
    let maximum = if name == "account" {
        ACCOUNT_ARGUMENT_BYTES
    } else {
        ORDINARY_ARGUMENT_BYTES
    };
    // Count exact serialized bytes without allocating a second large request.
    serde_json::to_writer(Count { used: 0, maximum }, value)
        .map_err(crate::error::Error::Invalid.redact())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "bounded/tests.rs"]
mod tests;
