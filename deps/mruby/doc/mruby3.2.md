# User visible changes in `mruby3.2` from `mruby3.1`

# The language

- Now `a::B = c` should evaluate `a` then `c`.
- Anonymous arguments `*`, `**`, `&` can be passed for forwarding.
- Multi-precision integer is available now via `mruby-bigint` gem.

# Tools

## `mruby`

- `-b` only specifies the script is the binary. The files loaded by `-r` are not affected by the option.
- `mruby` now loads complied binary if the suffix is `.mrb`.

## `mrbc`

- Add `--no-optimize` option to disable optimization.

# mrbgems

## mruby-errno

- `mruby-errno` gem is now bundled.

## mruby-class-ext

- Add `Class#subclasses` method.
- Add `Module#undefined_instance_methods` method.

# CVEs

Following CVEs are fixed.

- [CVE-2022-0481](https://nvd.nist.gov/vuln/detail/CVE-2022-0481)
- [CVE-2022-0525](https://nvd.nist.gov/vuln/detail/CVE-2022-0525)
- [CVE-2022-0570](https://nvd.nist.gov/vuln/detail/CVE-2022-0570)
- [CVE-2022-0614](https://nvd.nist.gov/vuln/detail/CVE-2022-0614)
- [CVE-2022-0623](https://nvd.nist.gov/vuln/detail/CVE-2022-0623)
- [CVE-2022-0630](https://nvd.nist.gov/vuln/detail/CVE-2022-0630)
- [CVE-2022-0717](https://nvd.nist.gov/vuln/detail/CVE-2022-0817)
- [CVE-2022-1212](https://nvd.nist.gov/vuln/detail/CVE-2022-1212)
- [CVE-2022-1276](https://nvd.nist.gov/vuln/detail/CVE-2022-1276)
- [CVE-2022-1286](https://nvd.nist.gov/vuln/detail/CVE-2022-1286)
