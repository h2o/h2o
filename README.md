# h2olog

A [varnishlog](https://varnish-cache.org/docs/trunk/reference/varnishlog.html)-like [BPF](https://www.kernel.org/doc/html/latest/bpf/index.html) ([kernel doc](https://www.kernel.org/doc/Documentation/networking/filter.txt)) backed HTTP request logging client for the [H2O](https://github.com/h2o/h2o) server.
h2olog can also be used to log [QUIC](https://en.wikipedia.org/wiki/QUIC) events for [transport layer](https://en.wikipedia.org/wiki/Transport_layer) observation.
See [Tracing QUIC events](#tracing-quic-events) for how.

## Installing from Source

See [requirements](#requirements) for build prerequisites.

```
$ cmake -Bbuild
$ make -Cbuild
$ sudo make -Cbuild install
```

If you have `BCC` installed to a non-standard path, give its path as [`-DCMAKE_PREFIX_PATH`](https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html) to `cmake`.

For convenience, you can alternatively run the `make.sh` script.

## Requirements

### For building h2olog

- LLVM and clang (>= 3.7.1)
- CMake for generating the build files
- Python 3 for the [code generator](https://github.com/toru/h2olog/blob/v2/misc/gen-quic-bpf.py)
- [BCC](https://iovisor.github.io/bcc/) (>= 0.11.0) [installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system

For Ubuntu 20.04 or later, you can install dependencies with:

```sh
sudo apt install clang cmake python3 systemtap-sdt-dev libbpfcc-dev linux-headers-$(uname -r)
```

### For running h2olog

- Root privilege to execute the program
- H2O server built after [53e1db42](https://github.com/h2o/h2o/commit/53e1db428772460534191d1c35c79a6dd94e021f) with `-DWITH_DTRACE=on` cmake option

## Quickstart

Root privilege is required to interact with the BPF virtual machine.

```
$ sudo h2olog -p $(pgrep -o h2o)

11 0 RxProtocol HTTP/3.0
11 0 RxHeader   :authority torumk.com
11 0 RxHeader   :method GET
11 0 RxHeader   :path /
11 0 RxHeader   :scheme https
11 0 TxStatus   200
11 0 TxHeader   content-length 123
11 0 TxHeader   content-type text/html
... and more ...
```

## Tracing QUIC events

Server-side [QUIC](https://en.wikipedia.org/wiki/QUIC) events can be traced using the `quic` subcommand.
Events are rendered in [JSON](https://en.wikipedia.org/wiki/JSON) format.

```
$ sudo h2olog quic -p $(pgrep -o h2o)
               ^
               |_ The quic subcommand
```

Here's an example trace.

```
{"time":1584380825832,"type":"accept","conn":1,"dcid":"f8aa2066e9c3b3cf"}
{"time":1584380825835,"type":"crypto-decrypt","conn":1,"pn":0,"len":1236}
{"time":1584380825832,"type":"quictrace-recv","conn":1,"pn":0}
{"time":1584380825836,"type":"crypto-handshake","conn":1,"ret":0}
... and more ...
```

## Program Anatomy

h2olog is a [BCC](https://github.com/iovisor/bcc) based C++ program.
It was previously implemented using the [BCC Python binding](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bcc-python).
