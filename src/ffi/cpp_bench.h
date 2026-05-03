/*
 * cpp_bench.h
 *
 * Pure-C++ fizz+folly echo benchmark used by `tls_bench_ablation` experiment 2a
 * to isolate the cost of the Rust binding (cxx + Tokio + per-conn evb threads)
 * from the cost of the fizz+folly stack itself.
 *
 * This entry point reuses the existing FizzServerContext / FizzClientContext
 * (built via the existing fizz_rs FFI) so the TLS configuration is identical
 * to the Rust `fizz` backend; only the orchestration differs.
 */

#pragma once

#define GLOG_USE_GLOG_EXPORT

#include <cstddef>
#include <cstdint>

struct FizzServerContext;
struct FizzClientContext;

uint64_t run_fizz_cpp_bench(
    const FizzServerContext& server_ctx,
    const FizzClientContext& client_ctx,
    uint64_t pairs,
    uint64_t batch_size,
    uint64_t rounds);
