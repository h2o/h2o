# How to contribute

We welcome third party contributions H2O. The most straightforward way to
do so, is to fork the project and submit a PR. If the change you're
proposing is substantial, it might be a good idea to open an issue in
the [issue tracker](https://github.com/h2o/h2o/issues) in order to
discuss it first.

# Coding style

## The C flavor

H2O is built on a multitude of platforms: \*BSD, Mac OS, Solaris and
Linux. It uses a dialect of C close to c89 and c99 intended to compile
on most gcc functions, and we avoid GNU extensions.

PRs are automatically built in [Travis](https://travis-ci.com/h2o/h2o),
and a test suite is run over the code. When possible, please add test
coverage to the code that you're submitting.

## Formatting

H2O uses [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html)
in order to maintain a uniform coding style on the code base, running
the tool before submitting might make the review process smoother.

To summarize, the coding style resembles the Linux kernel's with the
difference that it uses 4 spaces rather than one tab for indentation.

Here's a `.vimrc` snippet that would use this style:

```vim
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
```

## Naming


### Structs

Structs are prefixed with `st_` and suffixed with `_t`. Structs that are
not private to a single translation unit are typedef'ed and prefixed with
`h2o_`, and suffixed with `_t`:

```c
/* public struct */
typedef struct st_h2o_conn_t h2o_conn_t;

struct st_h2o_conn_t {
....
};

/* private struct */
struct st_on_client_hello_ptls_t {
...
};
```

### Functions

As with structs, publicly visible functions are prefixed with `h2o_`,
such as `h2o_process_request`, whereas private functions don't use one:
`get_ocsp_response`.

### Goto labels

Goto labels use upper case, and are indented with the matching code:

```c
void fn(const char *err)
{
    if (global) {
        if (err == NULL)
            goto Ok;

    Ok:
        this_is_ok();
    }
}
```

# Tests

H2O uses two main facilities for tests: unit tests in C and
integration tests written in perl. Both tests can be run with `make
check`. Some tests require to be run as root, and can be run with `make
check-as-root`. Please note that some tests need dependencies such as
curl or nghttp2, or some perl modules. You can refer to the `.travis.yml`
file for an example of how to install the dependencies.

Both kind of tests can be found under the `t/` directory.

## Unit tests

They are written an C and are found under the `t/00unit/` directory. They
use `picotest` [as a testing framework](https://github.com/h2o/picotest).

## Integration tests

Integration tests are found under the `t/` directory, and
are any file ending with `.t` extension. The test suite uses
[`Test::More`](https://perldoc.perl.org/Test/More.html) as a testing
framework. `t/Util.pm` offers facilities like running curl for all
supported protocols, spawning H2O or instantiating a backend server using
[Plackup](https://search.cpan.org/perldoc?plackup).

## Fuzzers

H2O is part of Google's OSS-Fuzz project, and as such H2O is continuously
fuzzed. Fuzzers are build when `cmake` is passed the `-DBUILD_FUZZER=ON`
flag, they use [libFuzzer](http://llvm.org/docs/LibFuzzer.html). Anything
that parses input from the network is a good candidate for fuzzing.

