use std::fs;
use std::fs::File;
use std::path::Path;
use std::process::Command;

/// Apply local patches under `patches/` to `third_party/fizz` without committing inside the submodule.
fn apply_one_patch(
    fizz_rs_directory: &str,
    fizz_dir: &str,
    patch_name: &str,
    already_applied: bool,
) {
    if already_applied {
        return;
    }
    let patch_path = format!("{fizz_rs_directory}/patches/{patch_name}");
    if !Path::new(&patch_path).exists() {
        println!("cargo:warning=fizz-rs patch not found at {patch_path}; see patches/README.md");
        return;
    }
    let status = Command::new("patch")
        .current_dir(fizz_dir)
        .args(["-p1", "-i", &patch_path])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=Applied patches/{patch_name} to third_party/fizz");
        }
        Ok(_) => panic!(
            "failed to apply {patch_path}; fix the patch or apply it manually under third_party/fizz"
        ),
        Err(e) => println!(
            "cargo:warning=could not run `patch` ({e}); apply {patch_path} manually if the build fails"
        ),
    }
}

/// See `patches/README.md`.
/// These are needed for blocking reasons, as an example, currently fizz's getdeps crashes when `openssl@1.1` is absent on Homebrew.
/// However, recent versions of Homebrew no longer ship openssl@1.1, so we need to apply this patch.
fn apply_fizz_patches(fizz_rs_directory: &str) {
    let fizz_dir = format!("{fizz_rs_directory}/third_party/fizz");

    let buildopts_path =
        format!("{fizz_rs_directory}/third_party/fizz/build/fbcode_builder/getdeps/buildopts.py");
    let openssl_done = fs::read_to_string(&buildopts_path).map_or(false, |c| {
        c.contains("homebrew_package_prefix(\"openssl@3\")")
            && c.contains("if candidate and os.path.exists(candidate)")
    });
    apply_one_patch(
        fizz_rs_directory,
        &fizz_dir,
        "fizz-homebrew-openssl.patch",
        openssl_done,
    );

    let manifest_path =
        format!("{fizz_rs_directory}/third_party/fizz/build/fbcode_builder/manifests/fizz");
    let pin_done = fs::read_to_string(&manifest_path).map_or(false, |m| {
        m.contains("rev = 034e4d3d3150bf1e245590cbc1e2988cca66eecd")
    });
    apply_one_patch(
        fizz_rs_directory,
        &fizz_dir,
        "fizz-getdeps-pin-git-rev.patch",
        pin_done,
    );
}

fn build_fizz() -> String {
    let fizz_rs_directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    apply_fizz_patches(&fizz_rs_directory);
    let fizz_directory = format!("{fizz_rs_directory}/third_party/fizz");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let install_dir = format!("{out_dir}/fizz-install");
    println!("cargo:warning=Building and installing fizz into {install_dir}");

    let output_file = File::create("/tmp/fizz.log").expect("failed to create /tmp/fizz.log");

    let status = Command::new("python3")
        .current_dir(fizz_directory)
        .arg("build/fbcode_builder/getdeps.py")
        .args(&["--scratch-path", &install_dir])
        .arg("--allow-system-packages")
        .args(&["build", "fizz"])
        .stdout(
            output_file
                .try_clone()
                .expect("could not clone /tmp/fizz.log"),
        )
        .stderr(output_file)
        .status()
        .expect("Error executing build fizz command!");

    if !status.success() {
        println!("cargo::error=Could not build fizz, logs available at /tmp/fizz.log");
        panic!("Could not build fizz, logs available at /tmp/fizz.log. Make sure you installed system-wide dependencies first (check README file)");
    }

    install_dir
}

/// Homebrew keg include path (e.g. glog/gflags are system deps, not under getdeps `installed/`).
fn homebrew_prefix(package: &str) -> Option<String> {
    let out = Command::new("brew")
        .args(["--prefix", package])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// Absolute paths to all the fizz dependencies in the scratch.
fn get_all_fizz_dependencies(fizz_install_dir: &str) -> Vec<String> {
    let mut fizz_dependencies = Vec::new();
    for path in fs::read_dir(format!("{fizz_install_dir}/installed")).unwrap() {
        let path = fs::canonicalize(path.unwrap().path()).unwrap();
        let path = path.to_str().unwrap();
        println!("cargo:warning={}", path);
        fizz_dependencies.push(path.to_owned());
    }
    fizz_dependencies
}

// Build our FFI bridge (src/bridge.rs and src/ffif/*.cpp) using cxx_build.
fn build_bridge(fizz_dependencies: &Vec<String>) {
    // Build the CXX bridge
    let mut cxx = cxx_build::bridge("src/bridge.rs");

    // Add compiler flags.
    cxx.warnings(false)
        // Add C++ FFI implementation files
        .file("src/ffi/certificates_ffi.cpp")
        .file("src/ffi/util.cpp")
        .file("src/ffi/credentials_ffi.cpp")
        .file("src/ffi/server_tls_ffi.cpp")
        .file("src/ffi/client_tls_ffi.cpp")
        // Set C++ standard (Folly requires C++17)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("/std:c++17") // MSVC
        // Add include directories
        .include("src"); // For ffi/*.h headers

    // Add include directory of all fizz dependencies
    for path in fizz_dependencies {
        cxx.include(format!("{}/include", path));
    }

    // System deps used by FFI/Folly headers when getdeps used `--allow-system-packages` (not under `installed/`).
    #[cfg(target_os = "macos")]
    {
        // `fmt` must be on the include path so `__has_include(<fmt/format.h>)` succeeds in
        // folly/Range.h; otherwise FMT_VERSION is unset (treated as 0) but fmt:: symbols are still referenced.
        for pkg in [
            "glog",
            "gflags",
            "boost",
            "openssl@3",
            "fmt",
            "double-conversion",
            "libevent",
        ] {
            if let Some(prefix) = homebrew_prefix(pkg) {
                cxx.include(format!("{}/include", prefix));
            }
        }
    }

    // Compile the bridge library
    cxx.compile("fizz_rs_bridge");
}

fn main() {
    // Build fizz and install it and dependencies in the given directory.
    let fizz_install_dir = build_fizz();
    let fizz_dependencies = get_all_fizz_dependencies(&fizz_install_dir);

    // Build CXX bridge
    build_bridge(&fizz_dependencies);

    // Link against required libraries
    println!("cargo:rustc-link-lib=fizz");
    println!("cargo:rustc-link-lib=folly");
    // libunwind is a separate GNU/Linux-style library; macOS unwind is provided by the system/C++ runtime.
    #[cfg(not(target_os = "macos"))]
    println!("cargo:rustc-link-lib=unwind");
    println!("cargo:rustc-link-lib=lzma");
    println!("cargo:rustc-link-lib=oqs");
    println!("cargo:rustc-link-lib=fmt");
    println!("cargo:rustc-link-lib=event");
    println!("cargo:rustc-link-lib=double-conversion");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=glog");
    println!("cargo:rustc-link-lib=gflags");
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rustc-link-lib=pthread");
    // Apple Clang uses libc++ (`-lc++`); GNU toolchains typically use libstdc++ (`-lstdc++`).
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=c++");
    #[cfg(not(target_os = "macos"))]
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=boost_context"); // Required by Folly

    // Add library search paths (adjust as needed for your system)
    // These may need to be customized based on installation location
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    }

    // Add lib directories for all fizz dependencies
    for path in &fizz_dependencies {
        println!("cargo:rustc-link-search=native={}/lib", path);
        println!("cargo::rustc-link-arg=-Wl,-rpath,{}/lib", path);
    }

    // Rerun build script if any of these files change
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=src/ffi/certificates_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/util.cpp");
    println!("cargo:rerun-if-changed=src/ffi/util.h");
    println!("cargo:rerun-if-changed=src/ffi/credentials_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/server_tls_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/client_tls_ffi.cpp");
    println!("cargo:rerun-if-changed=patches/fizz-homebrew-openssl.patch");
    println!("cargo:rerun-if-changed=patches/fizz-getdeps-pin-git-rev.patch");
}
