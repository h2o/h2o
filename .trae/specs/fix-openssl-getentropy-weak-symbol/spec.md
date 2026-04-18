# Fix OpenSSL getentropy Weak Symbol Spec

## Why
在 OpenBSD 平台上静态链接 H2O 和 OpenSSL 时，依然发生 `SIGSEGV at 0x0` 崩溃。通过前几次修复，我们已经处理了 `getauxval` 和 `getrandom` 这两个在 OpenBSD libc 中不存在的函数。但实际上，OpenSSL (如 1.1.1 和 3.0) 同样将 `getentropy` 声明为弱符号（Weak Symbol）。虽然 OpenBSD 原生支持 `getentropy`，但如果没有任何代码（如主程序）对其进行强引用（Strong Reference），静态链接器（`ld`）在处理 `libc.a` 时会因为只有弱引用而跳过提取该目标文件。最终，`getentropy` 在运行时的地址依然是 `0x0`。随后，由于编译器的激进优化（去除了 `if (getentropy != NULL)` 的防御性检查），OpenSSL 直接执行空指针导致程序崩溃。

## What Changes
- 在 `src/main.c` 的防优化不可达代码块中（`if (dummy_zero != 0)`），增加对 `getentropy` 的真实强引用调用。
- 这将强迫静态链接器从 `libc.a` 中将原生的 `getentropy` 系统调用实现完整地打包进二进制文件中，从而确保它在运行时的地址非空。

## Impact
- Affected specs: OpenBSD 静态链接兼容性
- Affected code: `src/main.c`

## ADDED Requirements
### Requirement: Strong Reference to getentropy
The system SHALL provide a strong reference to `getentropy` in the `main` function to ensure static linking of the symbol on OpenBSD.

#### Scenario: Success case
- **WHEN** user compiles h2o statically with OpenSSL on OpenBSD
- **THEN** the `getentropy` symbol is successfully resolved from `libc.a`, preventing the `SIGSEGV at 0x0` crash during random number generation.
