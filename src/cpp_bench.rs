//! Pure-C++ fizz+folly echo benchmark — see `src/ffi/cpp_bench.{h,cpp}`.
//!
//! Bypasses Tokio entirely: the Rust caller hands two already-built TLS
//! contexts to the C++ benchmark, which runs the whole echo workload on its
//! own folly EventBase threads and returns the wall clock in microseconds.
//! Only the call into `run` and its return cross the FFI boundary.

use crate::bridge::ffi;
use crate::client_tls::ClientTlsContext;
use crate::error::{FizzError, Result};
use crate::server_tls::ServerTlsContext;

/// Run `pairs` concurrent echo conversations of `rounds` rounds at
/// `batch_size` bytes each, using the provided server/client contexts.
/// Returns wall time in microseconds (measured inside the C++ runtime, but
/// callers are free to also wrap with `Instant::now` for an outer measurement).
pub fn run(
    server_ctx: &ServerTlsContext,
    client_ctx: &ClientTlsContext,
    pairs: u64,
    batch_size: u64,
    rounds: u64,
) -> Result<u64> {
    ffi::run_fizz_cpp_bench(
        server_ctx.cxx_ref(),
        client_ctx.cxx_ref(),
        pairs,
        batch_size,
        rounds,
    )
    .map_err(|e| FizzError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
}
