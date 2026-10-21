# AGENTS.md

Fork of [h2o/h2o](https://github.com/h2o/h2o) — fast HTTP/1.x, HTTP/2, HTTP/3 server + library, C99, CMake.

**Branch model:** `master` is the fork's line: upstream's `master` merged in, plus the fork's own changes
(the OpenSSL-3 provider port of neverbleed, the OpenBSD `pledge` support, the CI repairs, and the fixes of the
2026-10 security audit). `upstream` is a configured remote — `git fetch upstream master` then merge when
syncing. The fork is no longer a mirror of upstream, so do not assume `master` equals upstream.

Detailed, validated build/test/CI notes: `.github/copilot-instructions.md` (ignore its file-size figures —
`CMakeLists.txt` is ~1.1k lines, `include/h2o.h` ~2.5k).

## This machine (Windows host)

- Toolchain comes from MSYS2 clang64 on `PATH` (`H:\msys64`): clang, cmake, make, perl are available; gcc, ruby, Docker, and any WSL distro are NOT.
- The MSYS2 `msys` environment *does* have a POSIX gcc (`H:\msys64\usr\bin\gcc.exe`) and POSIX headers, so
  `gcc -fsyntax-only` works as a fast compile check of changed sources; it cannot link (no OpenSSL for that
  environment), so it verifies syntax, not the build.
- h2o targets POSIX systems and is not a supported Windows target, so the full build/test/CI pipeline cannot run here. For full verification use CI on Linux; on this box stick to reading/static analysis or MSYS2 experiments you confirm yourself.

## Build & test

- Submodules are mandatory and several show persistent ` m` in `git status` even after a clean checkout — don't treat that as your own change:
  ```sh
  git submodule update --init --recursive
  ```
- Standard build:
  ```sh
  cmake -B build && cmake --build build -j
  ```
- `make check` (from `build/`) depends on the `checkdepends` target, which builds test-support artifacts too (lib-examples, h2get, picotls-cli, quicly-cli, fuzzers). Don't run `make check` without it.
- Single unit test (fast, reliable): build, then run e.g. `./build/t-00unit-evloop.t` directly. Perl e2e tests (`t/5*.t`) need Perl with Test::More, Test::TCP, Starlet, Protocol::HTTP2, plus system tools (curl, nc, redis-server, memcached) — they assume a Linux/Docker environment.
- Test categories by prefix in `t/`: `00` unit, `10` module e2e, `40` protocol, `50` e2e, `80` issue regression.
- Unit tests live in `t/00unit/lib/<path>/<file>.c` and `#include` the source they exercise; a source that is
  included that way must be removed from the library sources in `CMakeLists.txt` (`LIST(REMOVE_ITEM
  UNIT_TEST_SOURCE_FILES ...)`), or the symbols are defined twice.

## CI coupling to watch

- All CI runs inside Docker via `misc/docker-ci/check.mk` (privileged, IPv6-enabled; targets: `ALL`, `ossl1.1.0+fuzz`, `ossl1.1.1`, `ossl3.0`, `boringssl`, `optional-features`, `asan`, `ubsan`, `coverage`).
- `check.mk` pins `SERVER_FEATURES_*` — the exact `*: YES` list that `h2o --version` must print (compared by `t/Util.pm` via `EXPECTED_SERVER_FEATURES`). If a build option changes that feature list, update the matching variable in `check.mk` or every affected CI job bails out with a feature-set mismatch.
- `pledge` is advertised only where pledge(2) exists (OpenBSD); it is deliberately absent from the Linux feature sets.
- `optional-features` is the only job compiling `WITH_NEVERBLEED=ON` / `WITH_BROTLI=OFF` — code guarded by those switches compiles one way everywhere else.
- `t/60find-doc.t` compares the directives that the built server reports with the ones that are documented, so a
  configurator command that is registered only under some build options makes every job fail unless the directive is
  registered unconditionally.
- `t/80issues3479.t` is timing-dependent (it depends on which file descriptors happen to be free) and fails
  intermittently in one job; a re-run of the failed job settles it.
- The `OpenSSL 1.1.0 + Fuzz` job is the slowest and the fuzzers make the suite slower; a failure there is often a
  timing artefact rather than a regression.

## The vendored neverbleed

`deps/neverbleed` is the fork's own copy of neverbleed's OpenSSL 3 provider variant (upstream still uses the
ENGINE API, which OpenSSL 4.0 and LibreSSL 3.9 no longer provide). A key that belongs to that provider is *not* a
key of the legacy API: `EVP_PKEY_get1_EC_KEY()` returns NULL for it, and picotls's
`ptls_openssl_lookup_signature_schemes()` dereferences that result. Take the signature schemes of an identity
from its certificate, not from the private key that the provider holds. The local modifications are documented in
`deps/neverbleed/PATCHES.md`.

## Formatting & dependencies

- Run `misc/clang-format-diff.sh` on modified C files before committing (LLVM style, 4-space indent, 132 cols; excludes `deps/`).
- `deps/` is vendored (quicly, picotls, picohttpparser, neverbleed, mruby, …). libyaml and hiredis use the system copy when pkg-config finds one, falling back to vendored; brotli/zstd have no vendored copy and always require system libs.
- The vendored libyaml/hiredis headers must not be on the include path when the system library is linked against:
  the structures of the two differ between versions.

## Local agent state

- `.agent/` (`pins.md`, `gates.md`) is intentionally untracked durable agent state — don't commit or clean it. Record verified gates there per its schema.
