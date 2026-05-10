//! Contention-free ablation of `tls_bench`.
//!
//! `--pairs N` sets `clients = servers = connections = N`. The client runtime
//! and server runtime are separate, each sized to `N` workers and `N` blocking
//! threads — so total blocking threads across both runtimes is `2N`, matching
//! `max_blocking_threads = clients + servers`. At `N = 1` the workload is a
//! single client talking to a single server over a single connection, which is
//! the smallest configuration for flame graphing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use fizz_rs::{
    Certificate, CertificatePublic, ClientTlsContext, CredentialGenerator, ServerTlsContext,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Tcp,
    Rustls,
    Fizz,
    /// Pure-C++ fizz+folly delegated TLS, no Tokio / no cxx on the hot path.
    /// Used as the reference point for measuring binding overhead in 2a.
    FizzCpp,
}

fn backend_csv(b: Backend) -> &'static str {
    match b {
        Backend::Tcp => "tcp",
        Backend::Rustls => "rustls",
        Backend::Fizz => "fizz",
        Backend::FizzCpp => "fizz_cpp",
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "tls_bench_ablation",
    about = "Contention-free ablation: one worker per client + one per server, in two runtimes"
)]
struct Cli {
    /// Which TLS (or TCP) stack to exercise
    #[arg(long, value_enum)]
    backend: Option<Backend>,

    /// Run tcp, rustls, and fizz sequentially for the same parameters
    #[arg(long, default_value_t = false)]
    all_backends: bool,

    /// N = clients = servers = connections. Client and server runtimes each get
    /// N workers and N blocking threads (total blocking threads = 2N).
    #[arg(long, default_value_t = 1)]
    pairs: usize,

    /// Comma-separated list of pairs values to sweep (e.g. "1,2,4,8,16,32").
    /// When set, overrides `--pairs` and emits one CSV row per (backend, N).
    /// Each N rebuilds the two Tokio runtimes sized to N workers / N blocking
    /// threads, preserving the ablation invariant at every scale point.
    #[arg(long, value_delimiter = ',')]
    pairs_sweep: Option<Vec<usize>>,

    #[arg(long, default_value_t = 16 * 1024)]
    batch_size: usize,

    #[arg(long, default_value_t = 64)]
    rounds: usize,

    /// Full benchmark iterations to discard before timing
    #[arg(long, default_value_t = 0)]
    warmup: usize,

    /// Measured iterations (median wall time reported)
    #[arg(long, default_value_t = 3)]
    runs: usize,

    #[arg(long, default_value_t = false)]
    csv_header: bool,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn load_fizz_materials() -> Result<(
    CertificatePublic,
    fizz_rs::DelegatedCredentialData,
    fizz_rs::VerificationInfo,
    PathBuf,
)> {
    let dir = fixtures_dir();
    let cert_path = dir.join("fizz.crt");
    let key_path = dir.join("fizz.key");
    let cert = Certificate::load_from_files(
        cert_path.to_str().context("cert path utf-8")?,
        key_path.to_str().context("key path utf-8")?,
    )?;
    let cert_public =
        CertificatePublic::load_from_file(cert_path.to_str().context("cert path utf-8")?)?;
    let generator = CredentialGenerator::new(cert)?;
    let dc = generator.generate("tls-bench-ablation", 3600)?;
    let verification_info = dc.verification_info();
    Ok((cert_public, dc, verification_info, cert_path))
}

fn rustls_configs() -> Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| anyhow::anyhow!("rcgen: {e}"))?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_pkcs8 = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_pkcs8))
        .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?;

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|e| anyhow::anyhow!("root store: {e}"))?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok((Arc::new(server_config), Arc::new(client_config)))
}

async fn echo_serve<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let mut buf = vec![0u8; batch_size];
    for _ in 0..rounds {
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
    }
    Ok(())
}

async fn echo_client<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: S,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let buf = vec![0x5Au8; batch_size];
    let mut read_back = vec![0u8; batch_size];
    for _ in 0..rounds {
        stream.write_all(&buf).await?;
        stream.flush().await?;
        stream.read_exact(&mut read_back).await?;
    }
    Ok(())
}

// Bind synchronously so the address is known before the client runtime dials.
fn bind_listener() -> Result<(std::net::SocketAddr, std::net::TcpListener)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    Ok((addr, listener))
}

// Disable Nagle's algorithm. Without this, on loopback the kernel coalesces
// small writes (e.g. TLS record headers) and adds up to ~40 ms of latency per
// round-trip, which dominates the benchmark — especially at low pairs counts
// where there's no concurrent traffic to keep the pipe full. Applied to every
// backend (tcp / rustls / fizz / fizz_cpp) so the comparison stays
// apples-to-apples; for the fizz Rust binding the option persists at the
// socket level even after `take_raw_fd` hands the fd to C++.
fn nodelay(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("set TCP_NODELAY")
}

fn run_tcp(
    client_rt: &Runtime,
    server_rt: &Runtime,
    pairs: usize,
    batch_size: usize,
    rounds: usize,
) -> Result<()> {
    let (addr, std_listener) = bind_listener()?;
    let server_handle = server_rt.spawn(async move {
        let listener = TcpListener::from_std(std_listener)?;
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            let (stream, _) = listener.accept().await?;
            nodelay(&stream)?;
            set.spawn(async move { echo_serve(stream, batch_size, rounds).await });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let client_result = client_rt.block_on(async move {
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            set.spawn(async move {
                let stream = TcpStream::connect(addr).await?;
                nodelay(&stream)?;
                echo_client(stream, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let server_result = server_rt.block_on(server_handle);
    client_result?;
    server_result.context("server join")??;
    Ok(())
}

fn run_rustls(
    client_rt: &Runtime,
    server_rt: &Runtime,
    pairs: usize,
    batch_size: usize,
    rounds: usize,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
) -> Result<()> {
    let (addr, std_listener) = bind_listener()?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let dns = ServerName::try_from("localhost".to_string())
        .map_err(|_| anyhow::anyhow!("invalid ServerName"))?;

    let server_handle = server_rt.spawn(async move {
        let listener = TcpListener::from_std(std_listener)?;
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            let (stream, _) = listener.accept().await?;
            nodelay(&stream)?;
            let acceptor = acceptor.clone();
            set.spawn(async move {
                let tls = acceptor.accept(stream).await?;
                echo_serve(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let client_result = client_rt.block_on(async move {
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            let connector = connector.clone();
            let dns = dns.clone();
            set.spawn(async move {
                let tcp = TcpStream::connect(addr).await?;
                nodelay(&tcp)?;
                let tls = connector.connect(dns, tcp).await?;
                echo_client(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let server_result = server_rt.block_on(server_handle);
    client_result?;
    server_result.context("server join")??;
    Ok(())
}

fn run_fizz(
    client_rt: &Runtime,
    server_rt: &Runtime,
    pairs: usize,
    batch_size: usize,
    rounds: usize,
    server_ctx: Arc<ServerTlsContext>,
    client_ctx: Arc<ClientTlsContext>,
) -> Result<()> {
    let (addr, std_listener) = bind_listener()?;
    let server_handle = server_rt.spawn(async move {
        let listener = TcpListener::from_std(std_listener)?;
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            let (stream, _) = listener.accept().await?;
            nodelay(&stream)?;
            let ctx = server_ctx.clone();
            set.spawn(async move {
                let tls = ctx.accept_from_stream(stream).await?;
                echo_serve(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let client_result = client_rt.block_on(async move {
        let mut set = JoinSet::new();
        for _ in 0..pairs {
            let ctx = client_ctx.clone();
            set.spawn(async move {
                let tcp = TcpStream::connect(addr).await?;
                nodelay(&tcp)?;
                let tls = ctx.connect(tcp, "localhost").await?;
                echo_client(tls, batch_size, rounds).await
            });
        }
        while let Some(r) = set.join_next().await {
            r??;
        }
        Ok::<(), anyhow::Error>(())
    });

    let server_result = server_rt.block_on(server_handle);
    client_result?;
    server_result.context("server join")??;
    Ok(())
}

fn run_backend(
    backend: Backend,
    client_rt: &Runtime,
    server_rt: &Runtime,
    pairs: usize,
    batch_size: usize,
    rounds: usize,
    rustls: Option<(Arc<ServerConfig>, Arc<ClientConfig>)>,
    fizz: Option<(Arc<ServerTlsContext>, Arc<ClientTlsContext>)>,
) -> Result<()> {
    match backend {
        Backend::Tcp => run_tcp(client_rt, server_rt, pairs, batch_size, rounds),
        Backend::Rustls => {
            let (s, c) = rustls.as_ref().context("rustls configs missing")?;
            run_rustls(
                client_rt,
                server_rt,
                pairs,
                batch_size,
                rounds,
                s.clone(),
                c.clone(),
            )
        }
        Backend::Fizz => {
            let (s, c) = fizz.as_ref().context("fizz contexts missing")?;
            run_fizz(
                client_rt,
                server_rt,
                pairs,
                batch_size,
                rounds,
                s.clone(),
                c.clone(),
            )
        }
        Backend::FizzCpp => {
            let (s, c) = fizz.as_ref().context("fizz contexts missing")?;
            // Pure-C++ benchmark: bypass both Tokio runtimes; the C++ side
            // runs the workload on its own folly EventBase threads.
            fizz_rs::cpp_bench::run(
                s.as_ref(),
                c.as_ref(),
                pairs as u64,
                batch_size as u64,
                rounds as u64,
            )
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("fizz_cpp: {e}"))
        }
    }
}

fn median_ms(samples: &[Duration]) -> f64 {
    let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    ms.sort_by(f64::total_cmp);
    let mid = ms.len() / 2;
    if ms.is_empty() {
        return 0.0;
    }
    if ms.len() % 2 == 1 {
        ms[mid]
    } else {
        (ms[mid - 1] + ms[mid]) / 2.0
    }
}

fn build_runtime(workers: usize, blocking: usize, name: &'static str) -> Result<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(blocking)
        .thread_name(name)
        .enable_all()
        .build()
        .with_context(|| format!("tokio runtime: {name}"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let batch_size = cli.batch_size;
    let rounds = cli.rounds;
    let runs = cli.runs;

    let backends: Vec<Backend> = if cli.all_backends {
        vec![Backend::Tcp, Backend::Rustls, Backend::Fizz, Backend::FizzCpp]
    } else {
        vec![cli
            .backend
            .context("pass --backend or use --all-backends")?]
    };

    let pairs_values: Vec<usize> = match cli.pairs_sweep.as_ref() {
        Some(v) if !v.is_empty() => v.iter().map(|n| (*n).max(1)).collect(),
        _ => vec![cli.pairs.max(1)],
    };

    let rustls_cfgs = rustls_configs().ok();
    let fizz_ctxs = load_fizz_materials().ok().map(|(cp, dc, vi, ca_path)| {
        let server = ServerTlsContext::new(cp, dc).expect("fizz server ctx");
        let client = ClientTlsContext::new(vi, ca_path.to_str().unwrap()).expect("fizz client ctx");
        (Arc::new(server), Arc::new(client))
    });

    if cli.csv_header {
        println!(
            "backend,pairs,client_workers,server_workers,max_blocking_threads,batch_size,rounds,wall_ms,total_bytes,mb_per_s,error"
        );
    }

    for &pairs in &pairs_values {
    let client_rt = build_runtime(pairs, pairs, "ablation-client")?;
    let server_rt = build_runtime(pairs, pairs, "ablation-server")?;

    let client_workers = pairs;
    let server_workers = pairs;
    let max_blocking_threads = pairs + pairs;

    let total_bytes = 2u64
        .saturating_mul(pairs as u64)
        .saturating_mul(rounds as u64)
        .saturating_mul(batch_size as u64);

    for backend in backends.iter().copied() {
        if matches!(backend, Backend::Rustls) && rustls_cfgs.is_none() {
            eprintln!("rustls: skipping (failed to build configs)");
            println!(
                "{},{},{},{},{},{},{},,,,rustls_config_error",
                backend_csv(backend),
                pairs,
                client_workers,
                server_workers,
                max_blocking_threads,
                batch_size,
                rounds
            );
            continue;
        }
        if matches!(backend, Backend::Fizz | Backend::FizzCpp) && fizz_ctxs.is_none() {
            eprintln!(
                "{}: skipping (failed to load {} — run from repo with tests/fixtures)",
                backend_csv(backend),
                fixtures_dir().display()
            );
            println!(
                "{},{},{},{},{},{},{},,,,fizz_fixtures_error",
                backend_csv(backend),
                pairs,
                client_workers,
                server_workers,
                max_blocking_threads,
                batch_size,
                rounds
            );
            continue;
        }

        for _ in 0..cli.warmup {
            let _ = run_backend(
                backend,
                &client_rt,
                &server_rt,
                pairs,
                batch_size,
                rounds,
                rustls_cfgs.clone(),
                fizz_ctxs.clone(),
            );
        }

        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            let t0 = Instant::now();
            match run_backend(
                backend,
                &client_rt,
                &server_rt,
                pairs,
                batch_size,
                rounds,
                rustls_cfgs.clone(),
                fizz_ctxs.clone(),
            ) {
                Ok(()) => samples.push(t0.elapsed()),
                Err(e) => {
                    println!(
                        "{},{},{},{},{},{},{},,,,{}",
                        backend_csv(backend),
                        pairs,
                        client_workers,
                        server_workers,
                        max_blocking_threads,
                        batch_size,
                        rounds,
                        e.to_string().replace(',', ";")
                    );
                    samples.clear();
                    break;
                }
            }
        }

        if samples.is_empty() {
            continue;
        }

        let wall_ms = median_ms(&samples);
        let secs = wall_ms / 1000.0;
        let mb_per_s = if secs > 0.0 {
            (total_bytes as f64 / (1024.0 * 1024.0)) / secs
        } else {
            0.0
        };

        println!(
            "{},{},{},{},{},{},{},{:.3},{},{:.3},",
            backend_csv(backend),
            pairs,
            client_workers,
            server_workers,
            max_blocking_threads,
            batch_size,
            rounds,
            wall_ms,
            total_bytes,
            mb_per_s
        );
    }
    }

    Ok(())
}
