# H2O Copilot Instructions

## Repository Overview

H2O is an optimized HTTP server with support for HTTP/1.x, HTTP/2, and HTTP/3 (experimental). It is written in C and licensed under the MIT License. The repository consists of approximately 87,000 lines of C code (excluding dependencies) and can also be used as a library via libh2o.

**Repository Structure:**
- **Primary Language:** C (requires C compiler with C99 support)
- **Build System:** CMake (minimum version 2.8.12)
- **Codebase Size:** ~87K lines of C code (excluding deps)
- **License:** MIT

## Build Instructions

### Prerequisites

**Required Dependencies:**
- CMake 2.8.12 or higher
- C compiler (GCC or Clang)
- OpenSSL (1.1.0+ required; 1.0.2+ for HTTP/2 with browsers)
- zlib
- Git (for submodules)

**Optional Dependencies:**
- Ruby and Bison (for mruby support, enabled by default if available)
- libyaml-dev (automatically uses system version if available)
- ccache (for faster rebuilds, auto-detected)
- libuv (for libuv event loop support)
- liburing (for io_uring support on Linux)
- wslay (for WebSocket support)

**CRITICAL: Always initialize submodules before building:**
```bash
git submodule update --init --recursive
```

### Building from Source

**Standard Build Process (VALIDATED):**

1. **Initialize submodules (REQUIRED):**
   ```bash
   git submodule update --init --recursive
   ```

2. **Create build directory and configure:**
   ```bash
   mkdir -p build
   cd build
   cmake ..
   ```

3. **Build (use parallel jobs for faster builds):**
   ```bash
   make -j$(nproc)
   ```
   Build time: ~2-3 minutes on modern hardware with parallel jobs.

4. **Build output:**
   - Main executable: `build/h2o`
   - Test executables: `build/t-*.t`

**Build Options (CMAKE_ARGS):**
- `-DWITH_MRUBY=ON/OFF` - Enable/disable mruby support (default: ON if ruby+bison available)
- `-DWITH_CCACHE=ON/OFF` - Use ccache for faster rebuilds (default: auto-detected)
- `-DOPENSSL_ROOT_DIR=/path` - Specify OpenSSL location (auto-detected on macOS via Homebrew)
- `-DCMAKE_C_COMPILER=clang` - Specify C compiler
- `-DCMAKE_BUILD_TYPE=Debug/Release` - Build type (default: Release)

**Known Build Warnings (SAFE TO IGNORE):**
- Deprecation warnings for OpenSSL 3.0 DH functions (in src/main.c)
- Brotli VLA parameter warnings (in deps/brotli/)
- Unrecognized `-Wno-nullability-completeness` on GCC

## Testing

### Running Tests

**Unit Tests:**
Run individual unit test executable directly:
```bash
cd build
./t-00unit-evloop.t
```

**Full Test Suite:**
```bash
cd build
make check
```
**WARNING:** Full test suite takes 10-30+ minutes and requires:
- Perl 5.x with Test::More, Test::TCP, Starlet, Protocol::HTTP2
- Various system tools (curl, nc, redis-server, memcached, php-cgi)
- Network permissions for binding ports
- Some tests may fail outside Docker CI environment due to missing dependencies

**Recommended Testing Approach:**
For local validation, run only relevant unit tests or use Docker CI (see below).

### Test Organization (t/ directory)

Tests are numbered by category:
- `00*` - Unit tests (C-based, fast)
- `10*` - Module-level end-to-end tests
- `40*` - Protocol tests
- `50*` - End-to-end integration tests (Perl-based, slower)
- `80*` - Issue regression tests
- `90*` - Extended/author tests

**Test Runner:** `t/run-tests` (Perl script supporting parallel execution via `-j` flag)

## Continuous Integration

**GitHub Actions Workflow:** `.github/workflows/ci.yml`

All CI builds run inside Docker containers using configurations in `misc/docker-ci/`:
- **Default workflow command:**
  ```bash
  make -f misc/docker-ci/check.mk ALL BUILD_ARGS=-j6 TEST_ENV='TEST_JOBS=4'
  ```

**CI Test Matrix:**
1. `default` - Default OpenSSL + all features
2. `ossl1.1.0+fuzz` - OpenSSL 1.1.0 with fuzzer (uses Clang)
3. `ossl1.1.1` - OpenSSL 1.1.1
4. `ossl3.0` - OpenSSL 3.0 + DTrace (Ubuntu 24.04)
5. `boringssl` - Google BoringSSL
6. `asan` - Address Sanitizer build (Clang)
7. `coverage` - Code coverage (Clang with instrumentation)

**Docker CI Targets (misc/docker-ci/check.mk):**
- Require Docker with IPv6 support and privileged mode
- Mount tmpfs for faster test execution
- Timeout: 60 minutes per job

**To replicate CI locally (requires Docker):**
```bash
make -f misc/docker-ci/check.mk ALL BUILD_ARGS=-j6
```

## Code Formatting and Style

**Formatting Tool:** clang-format (version 3.6+)

**Configuration:** `.clang-format` (LLVM style, 4-space indent, 132 column limit)

**Run formatter on all files:**
```bash
./misc/clang-format-all.sh
```

**Run formatter on modified files only:**
```bash
./misc/clang-format-diff.sh
```

**Formatting rules:**
- Use clang-format before committing C code changes
- Script excludes: `deps/`, files starting with `_`, and `handler/mimemap/defaults.c.h`
- Column limit: 132 characters
- Indent width: 4 spaces
- Brace style: Linux (opening brace on same line for functions)

**Additional Style Notes:**
- Refer to wiki: https://github.com/h2o/h2o/wiki/Coding-Style
- Follow existing patterns in similar code sections

## Project Layout

### Key Directories

**Source Code:**
- `src/` - Main server executable source (main.c, ssl.c, httpclient.c)
- `lib/` - Core library implementation
  - `lib/core/` - Core functionality
  - `lib/common/` - Common utilities
  - `lib/handler/` - Request handlers (file, proxy, fastcgi, mruby, etc.)
  - `lib/http2/` - HTTP/2 implementation
  - `lib/http3/` - HTTP/3 implementation (QUIC)
- `include/` - Public headers
  - `include/h2o.h` - Main public API header (90K+ lines)
  - `include/h2o/` - Supporting headers

**Configuration and Build:**
- `CMakeLists.txt` - Root CMake configuration (46K+ lines, comprehensive)
- `.clang-format` - Code formatting rules
- `cmake/` - CMake find modules (LibUV, LibYAML, Mruby, Wslay)

**Testing:**
- `t/` - Test suite (Perl and C unit tests)
- `t/run-tests` - Test runner script (supports parallel execution)
- `t/README.md` - Test organization documentation

**Dependencies:**
- `deps/` - Vendored third-party libraries (29 subdirectories)
  - Notable: picotls, quicly, brotli, mruby, yaml
- `.gitmodules` - Git submodule configuration

**Documentation and Examples:**
- `doc/` - Generated documentation (HTML, man pages)
- `examples/` - Example configurations and code
- `README.md` - Project overview
- `CONTRIBUTING.md` - Contribution guidelines
- `SECURITY.md` - Security policy

**CI/Build Infrastructure:**
- `.github/workflows/ci.yml` - GitHub Actions CI configuration
- `misc/docker-ci/` - Docker-based CI infrastructure
  - `check.mk` - CI test execution targets
  - `build.mk` - Docker image build targets
  - `Dockerfile.ubuntu*` - Docker images for different Ubuntu versions

**Miscellaneous:**
- `misc/` - Helper scripts and tools
  - `misc/clang-format-all.sh` - Format all C code
  - `misc/clang-format-diff.sh` - Format modified files only
- `fuzz/` - Fuzzing targets (OSS-Fuzz integration)
- `share/` - Shared data files

### Root Directory Files

```
.clang-format          - Clang-format configuration
.dockerignore         - Docker build exclusions
.gitignore            - Git ignore patterns
.gitmodules           - Git submodule definitions
.vimrc                - Vim editor settings
CMakeLists.txt        - Root build configuration
CONTRIBUTING.md       - Contribution guide
Changes               - Changelog
LICENSE               - MIT license
README.md             - Project README
SECURITY.md           - Security disclosure policy
h2o-probes.d          - DTrace probe definitions
h2o.xcodeproj/        - Xcode project (macOS)
libh2o-evloop.pc.in   - pkg-config template for evloop
libh2o.pc.in          - pkg-config template
```

### Important Configuration Files

**Build:** `CMakeLists.txt` (root), `cmake/*.cmake`
**Linting:** `.clang-format`
**CI:** `.github/workflows/ci.yml`, `misc/docker-ci/check.mk`
**Testing:** `t/run-tests` (test orchestration)

## Common Pitfalls and Solutions

### Build Issues

**Problem:** Build fails with missing submodules
**Solution:** Always run `git submodule update --init --recursive` before building

**Problem:** OpenSSL not found on macOS
**Solution:** Install via Homebrew (`brew install openssl`) or set `OPENSSL_ROOT_DIR`

**Problem:** Build warnings about deprecated OpenSSL functions
**Solution:** These are expected with OpenSSL 3.0; they are safe to ignore

**Problem:** Missing ruby/bison but want mruby support
**Solution:** Install Ruby and Bison, then reconfigure with `cmake -DWITH_MRUBY=ON`

### Testing Issues

**Problem:** Tests timeout or hang
**Solution:** Some tests require network services (memcached, redis). Run in Docker CI for full suite.

**Problem:** Individual test failures in local build
**Solution:** Some tests expect specific environment setup. Unit tests (t-00unit*.t) are most reliable locally.

**Problem:** `make check` takes too long
**Solution:** Run specific test files or use Docker CI which is optimized for parallel testing

### Code Changes

**Problem:** Forgot to run clang-format
**Solution:** Run `./misc/clang-format-all.sh` before committing

**Problem:** Need to add new dependency
**Solution:** Prefer system packages. Check CI Dockerfiles for install commands. Update CMakeLists.txt accordingly.

**Problem:** Changes break CI but work locally
**Solution:** Test locally with Docker CI: `make -f misc/docker-ci/check.mk ALL BUILD_ARGS=-j6`

## Working Efficiently

**Before Making Changes:**
1. Initialize submodules if not done: `git submodule update --init --recursive`
2. Understand the build process: examine `CMakeLists.txt` and relevant sections
3. Identify which component you're modifying (lib/handler, lib/http2, lib/http3, etc.)

**Development Workflow:**
1. Make surgical, minimal changes
2. Build incrementally: `cd build && make -j$(nproc)`
3. Run relevant unit tests: `./t-00unit-*.t`
4. Format code: `./misc/clang-format-all.sh`
5. For major changes, test with Docker CI

**Validation Before Committing:**
1. Build succeeds without errors
2. Relevant tests pass
3. Code is formatted with clang-format
4. No unnecessary changes to unrelated files

**When Searching the Codebase:**
- Main API: `include/h2o.h` and `include/h2o/*.h`
- Handler implementations: `lib/handler/`
- Protocol logic: `lib/http1.c`, `lib/http2/`, `lib/http3/`
- Configuration parsing: `lib/handler/configurator/`
- Server entry point: `src/main.c`

## Trust These Instructions

These instructions are validated against the actual build and test process. When you encounter a build or test issue:

1. First, check if the instruction here addresses it
2. Only search the codebase if the issue is not covered or instructions are incomplete
3. When in doubt, examine the CI workflow (`.github/workflows/ci.yml`) and Docker CI configs (`misc/docker-ci/`)

The information here represents the authoritative build and test process. Deviation from these steps may result in failures not seen in CI.
