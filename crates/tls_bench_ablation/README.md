# tls_bench_ablation

This crate is the primary fizz_rs benchmark. It runs the same echo workload across four backends (`tcp`, `rustls`, `fizz`, `fizz_cpp`) and arranges the Tokio runtime so that no worker thread ever has to multiplex more than one task. The goal is twofold:

1. **Strip scheduling and blocking-pool contention** out of the Tokio-side picture so that whatever overhead remains in the `fizz` (Rust binding, delegated) backend is attributable to the work itself: the CXX FFI bridge, copies across the Rust/C++ boundary, crypto, record handling, and synchronous waiting inside the delegated path.
2. **Compare the Rust binding directly to a pure-C++ baseline** (`fizz_cpp`) running the identical echo workload through fizz+folly without Tokio, without cxx, and without per-connection event-loop threads. The gap between `fizz` and `fizz_cpp` is, by construction, the cost of the binding rather than the cost of fizz+folly itself.

Put differently: this crate asks "what is the floor? What does a single TLS conversation cost when nothing is fighting over a worker — and how much of that cost is fizz, vs how much is the wrapper around it?"

## Design: one knob, two runtimes

There is one parameter that controls concurrency: `--pairs N`. It sets

```
clients = servers = connections = N
```

by construction. The benchmark then builds two Tokio multi-thread runtimes that share no threads:

- **client runtime**: `N` worker threads, `N` blocking threads, threads named `ablation-client`
- **server runtime**: `N` worker threads, `N` blocking threads, threads named `ablation-server`

Total blocking threads across both runtimes is `2N`, which matches the `max_blocking_threads = clients + servers` rule from the ablation spec. Server handlers never run on the same worker as clients, and the blocking pool each side uses for `spawn_blocking` (which the `fizz` backend needs for accept and connect) is sized exactly to its own demand.

The default is `--pairs 1`. At that setting you have one client talking to one server over one connection, with one worker on each side and one blocking thread available to each side. Every thread in the process has a dedicated, unambiguous job. That is the smallest configuration and the most flame-graph-friendly one: it produces a narrow profile where each frame corresponds to a specific responsibility.

## What it measures

The server listener is bound synchronously so the address is known before the client runtime starts dialing. The `std::net::TcpListener` is handed to the server runtime and converted to a `tokio::net::TcpListener` there — that single file descriptor is the only thing the two runtimes share. Each side then runs its half of the workload on its own runtime.

Timing covers the whole scenario. Wall clock starts just before the first client task is spawned and stops once every client and every server handler has finished (including the TLS handshake on each side for `rustls` and `fizz`). Each client performs `rounds` echo cycles of `batch_size` bytes in each direction. The tool runs the scenario `--runs` times after `--warmup` passes and reports the median wall time. Throughput is derived from `total_bytes = 2 * pairs * rounds * batch_size` divided by that median. For numbers you care about, build with `--release`.

Because this crate shares the exact `echo_serve` and `echo_client` implementations with `tls_bench`, you can cross-compare: the same workload in one shared runtime vs. the same workload split across two sized runtimes. A gap that stays large on the `fizz` backend in both setups is a gap you cannot explain away with scheduling pressure.

## Prerequisites

Run Cargo from the fizz-rs-dev repository root. This crate depends on `fizz_rs` via `../..`, so the workspace layout matters. The `fizz` backend expects the same PEM fixtures as the library tests: `tests/fixtures/fizz.crt` and `tests/fixtures/fizz.key` under the repo root. If those files are missing, the tool still runs but skips `fizz` and records an error in the CSV. Compiling `tls_bench_ablation` compiles all of `fizz_rs`, including the native Fizz build from `build.rs`, so the first build can take a long time.

## The `fizz_cpp` baseline

The `fizz_cpp` backend runs the same echo workload entirely in C++: a `folly::AsyncServerSocket` accepts on a shared server `EventBase` thread, each connection wraps in `AsyncFizzServer` / `AsyncFizzClient`, the handshake and the read/write loops run as ordinary fizz/folly callback chains, and a small `EchoServerSession` / `EchoClientSession` per conn drives `rounds` of echo via `writeChain` / `ReadCallback`. No Tokio, no cxx round-trips on the hot path, no Rust async. Only the call into `run_fizz_cpp_bench` and its return cross the FFI.

This makes `fizz_cpp` the apples-to-apples baseline for the Rust binding (`fizz`) — same TLS configuration (delegated credentials, identical `FizzServerContext` / `FizzClientContext` constructed on the Rust side and handed to C++), same workload, same crypto. The only thing that differs is what sits between the application code and fizz: an idiomatic C++ event loop (`fizz_cpp`) versus a Rust async wrapper that bridges Tokio to fizz/folly (`fizz`). The implementation lives at `src/ffi/cpp_bench.{h,cpp}` in the parent crate.

The `fizz_cpp` backend currently only supports the delegated-credential configuration. A non-delegated variant is feasible but not yet wired up.

## Command-line options

You must pass either `--backend` with one of `tcp`, `rustls`, `fizz`, or `fizz_cpp`, or `--all-backends` to run all four in sequence with the same numeric settings.

`--pairs N` is the concurrency knob (default 1). It simultaneously sets the number of clients, the number of server handlers, the number of connections, both per-runtime worker counts, and both per-runtime blocking-thread pools. Increase it only if you want to see how the ablated arrangement scales; for profiling, leave it at 1.

`--pairs-sweep "1,2,4,8,16,32"` runs a scaling sweep: each value of N rebuilds the two Tokio runtimes sized to N workers / N blocking threads (preserving the ablation invariant at every scale point) and emits one CSV row per `(backend, N)` combination. When set, this overrides `--pairs`. Use this to plot Rust-binding-vs-C++ scaling curves directly.

`--batch-size` is the echo payload size in bytes (default 16384). `--rounds` is how many echo cycles each client performs (default 64). `--warmup` is how many full runs to execute before recording (default 0). `--runs` is how many timed runs feed the median (default 3). With `--csv-header`, the first line of output is a column header row.

There are no presets here. The ablation is deliberately a single axis.

## CSV output

Each result line contains, in order: `backend`, `pairs`, `client_workers`, `server_workers`, `max_blocking_threads`, `batch_size`, `rounds`, `wall_ms`, `total_bytes`, `mb_per_s`, and `error`. The three worker-related columns are redundant with `pairs` by construction (they hold `pairs`, `pairs`, and `2 * pairs` respectively), but they are kept explicit so the CSV is self-describing and can be joined against `tls_bench` output without recomputation. The backend name is always lowercase. The error field is empty on success; otherwise it holds a short code or message with commas stripped so the line stays parseable as CSV.

## Examples

From the repo root, the smallest case with a header row — one client, one server, one connection, all four backends:

```bash
cargo run -p tls_bench_ablation --release -- --csv-header --all-backends
```

**Scaling sweep, Rust binding vs. C++ baseline at multiple connection counts.** This is the headline experiment for measuring how the binding scales relative to idiomatic fizz+folly:

```bash
cargo run -p tls_bench_ablation --release -- \
  --csv-header --all-backends \
  --pairs-sweep "1,2,4,8,16,32" \
  --batch-size 65536 --rounds 64 --warmup 1 --runs 5
```

The CSV emits one row per `(backend, N)` and is plot-friendly. Look at the `fizz` and `fizz_cpp` rows side by side: their gap at each N is the binding overhead at that scale.

Flame-graph-friendly profiling of the `fizz` backend at 1-1-1. With named runtime threads, client-side and server-side frames are trivially distinguishable in the resulting graph:

```bash
cargo build -p tls_bench_ablation --release
samply record ./target/release/tls_bench_ablation \
  --backend fizz --pairs 1 --runs 1 --warmup 0 \
  --batch-size 65536 --rounds 256
```

Substitute `cargo flamegraph -p tls_bench_ablation --release -- ...` if you prefer that tool. Longer `--rounds` gives the profiler more signal once the handshake is past.

Single point at `pairs=8`, all four backends, useful when you want a quick read at a specific N:

```bash
cargo run -p tls_bench_ablation --release -- --csv-header --all-backends \
  --pairs 8 --batch-size 65536 --rounds 32 --runs 5
```

## Reading the results

Four backends, two questions:

- **`fizz` vs `rustls`** answers "how does our delegated TLS implementation compare against a Rust-native non-delegated TLS?" That gap mixes "delegation cost" with "binding cost" with "library cost" — so it's a useful headline number but not a clean attribution.
- **`fizz` vs `fizz_cpp`** answers "how much of the gap is the binding?" `fizz_cpp` runs the same delegated TLS workload through the same fizz+folly libraries; the only thing that changes is whether the workload is driven from Rust async via cxx, or directly in C++ on a folly EventBase. Subtract `fizz_cpp` from `fizz` and you have the binding's price tag.
- **`fizz_cpp` vs `rustls`** is the small remainder. In practice this gap is close to zero, which means delegated credentials in fizz+folly are roughly free at steady state — the cost a real deployment pays is almost entirely the wrapper.

For scaling, the sweep flag emits one row per N. Plot `mb_per_s` vs `pairs`, one line per backend, and the relative shapes of the `fizz` and `fizz_cpp` curves directly visualize how the binding overhead behaves as the workload scales out. (At small N the per-conn evb-thread cost is fixed; at larger N parallelism across evbs vs. the fizz_cpp shared evb starts to matter — the shapes diverge in interesting ways.)

