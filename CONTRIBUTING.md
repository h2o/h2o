   * [How to contribute](#how-to-contribute)
   * [Coding style](#coding-style)
      * [The C flavor](#the-c-flavor)
      * [Formatting](#formatting)
      * [Naming](#naming)
         * [Structs](#structs)
         * [Functions](#functions)
         * [Goto labels](#goto-labels)
      * [Context passing and subclassing](#context-passing-and-subclassing)
         * [Subclassing](#subclassing)
         * [Context passing using struct member offsets](#context-passing-using-struct-member-offsets)
   * [Tests](#tests)
      * [Unit tests](#unit-tests)
      * [Integration tests](#integration-tests)
      * [Fuzzers](#fuzzers)
   * [Writing docs](#writing-docs)

# How to contribute

We welcome third party contributions H2O. The most straightforward way to
do so, is to fork the project and submit a PR. If the change you're
proposing is substantial, it might be a good idea to open an issue in
the [issue tracker](https://github.com/h2o/h2o/issues) in order to
discuss it first.

By submitting a pull request, you agree to license the submitted code under
[the MIT License](https://opensource.org/licenses/MIT). If you do not own
the copyright of the code that is being submitted, please clarify the name
of the copyright holder and the license under which the copyrighted
material can be used so that we can review if it could be incorporated as
part of the H2O project.

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
the tool before submitting might make the review process smoother. The
formatting command can be invoked over all the repository by the following
command: `make -f misc/regen.mk clang-format-all`

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
found in public headers are typedef'ed and prefixed with `h2o_`, and
suffixed with `_t`:

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

## Context passing and subclassing

### Subclassing

The H2O code base tends to use subclassing in order to pass contextual
information. For example, both `h2o_http2_conn_t` and `struct
st_h2o_http1_conn_t` are subclasses of `h2o_conn_t`. They do so by
defining a `super` member of the struct of type `h2o_conn_t`, and
returning that outside their respective modules. The struct is then cast
back to the specilized subclasses when returning to their modules.

This is in turn used so that both the HTTP/1 and HTTP/2 connections are
able to expose a common interface for `get_sockname`, for example:

```c
/* http2 */
static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    ...
}

/* http1 */
static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http1_conn_t *conn = (void *)_conn;
    ...
}
```

This way upper layers can act on an `h2o_conn_t` without exposing the
details of `h2o_http2_conn_t` or `struct st_h2o_http1_conn_t`.

### Context passing using struct member offsets

Another technique commonly used in the H2O code base is offset
calculations. This allows to better performance and reduced public interfaces, while
still being able to pass objects of different types. H2O
uses the `H2O_STRUCT_FROM_MEMBER` macro (which in turn uses
[`offsetof`](https://en.wikipedia.org/wiki/Offsetof)) in order to
compute the offset of a member in a struct. This way, given a pointer to
a member, we can obtain a pointer to the enclosing struct.

Linked lists (`h2o_linklist_t`) and timers (`h2o_timeout_entry_t`)
are typical users of the technique.

Here's an example demonstrating how to pass context alongside a timer pointer:
```c
struct st_mycontext_t {
  void *ctx;
  h2o_timeout_entry_t timer;
};

void timer(h2o_timeout_entry_t *t)
{
    struct st_mycontext_t *mc = H2O_STRUCT_FROM_MEMBER(struct st_mycontext_t, timer, t);
    ...
}
void f(struct st_mycontext_t *mc)
{
    mc->timer.cb = timer;
    mc->ctx = alloc_context();
    h2o_timeout_link(loop, io_timeout, &mc->timer);
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

Single tests can be run manually by running `perl t/<test>.t`, in which
case, you might have to set the environment variable `H2O_ROOT` to the
root of the H2O repository, since some tests rely on it.

## Fuzzers

H2O is part of Google's OSS-Fuzz project, and as such H2O is continuously
fuzzed. Fuzzers are build when `cmake` is passed the `-DBUILD_FUZZER=ON`
flag, they use [libFuzzer](http://llvm.org/docs/LibFuzzer.html). Anything
that parses input from the network is a good candidate for fuzzing.

# Writing docs

The H2O repository contains source docs in the form of `.mt` template
files, as well the generated docs. The source docs can be found under
`srcdoc/` and the generated ones can be found under `doc/`.

The `.mt` files, use a templating DSL built on top of
[Text::MicroTemplate](https://github.com/kazuho/p5-text-microtemplate)
The DSL defines methods such as `code`, `example`, `directive` which
are used to write the documentation. All those directives are defined in
[`makedoc.pl`](https://github.com/h2o/h2o/blob/master/misc/makedoc.pl).

Docs are generated by running `make` in the `doc/` directory.
