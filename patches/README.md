# Submodule Patches

To keep our submodule dependencies (primarily fizz) up to date and non-breaking on modern systems and OS versions, there are some changes we need to make to their build systems. To ensure these changes are reproducible, we add them as patches in this directory which are applied by `build.rs` before `getdeps` runs (no need to commit edits inside `third_party/fizz`).

- **`fizz-homebrew-openssl.patch`** — `getdeps` assumed `openssl@1.1`; current Homebrew often only has `openssl@3`, which made `os.path.exists(None)` crash. Prefer `@3`, fall back to `@1.1`, guard `None`.

- **`fizz-getdeps-pin-git-rev.patch`** — The Fizz manifest has no `[git] rev`, so getdeps clones **main** from GitHub while `build/deps/github_hashes/facebook/folly-rev.txt` pins an older Folly. That mismatch breaks the build (e.g. `AsyncSocketTransport::BindOptions`). The patch pins `[git] rev` to match the **current `third_party/fizz` submodule**; if you update the submodule, refresh this patch’s hash to match `git rev-parse HEAD` in `third_party/fizz`.