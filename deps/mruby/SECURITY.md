# Security Policy

## Reporting a Vulnerability

If you have any security concern, contact <matz@ruby.or.jp>.

## Scope

We consider following issues as vulnerabilities:

* Remote code execution
* Crash caused by a valid Ruby script

We *don't* consider following issues as vulnerabilities:

* Runtime C undefined behavior (including integer overflow)
* Crash caused by misused API
* Crash caused by modified compiled binary
* ASAN/Valgrind warning for too big memory allocation
  mruby assumes `malloc(3)` returns `NULL` for too big allocations
