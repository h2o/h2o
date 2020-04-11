# h2olog

A [varnishlog](https://varnish-cache.org/docs/trunk/reference/varnishlog.html)-like [BPF](https://www.kernel.org/doc/html/latest/bpf/index.html) ([kernel doc](https://www.kernel.org/doc/Documentation/networking/filter.txt)) backed HTTP request logging client for the [H2O](https://github.com/h2o/h2o) server.

## Installing from Source

See [requirements](#requirements) for build prerequisites.

```
$ cmake .
$ make
$ sudo make install
```

For convenience, you can alternatively run the `make.sh` script.

## Requirements

### For building h2olog

- LLVM and clang (>= 3.7.1)
- CMake for generating the build files
- Python 3 for the [code generator](https://github.com/toru/h2olog/blob/v2/misc/gen-bpf.py)
- [BCC](https://iovisor.github.io/bcc/) (>= 0.11.0) [installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system

### For running h2olog

- Root privilege to execute the program
- H2O server built after [53e1db42](https://github.com/h2o/h2o/commit/53e1db428772460534191d1c35c79a6dd94e021f)

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

If you find the output to be too noisy, try using the `-t` option to only trace a specific event type.

```
$ sudo h2olog quic -t quicly:accept -p $(pgrep -o h2o)

{"time":1584381666657,"type":"accept","conn":2,"dcid":"704e7cdd80815ab8"}
{"time":1584381667155,"type":"accept","conn":1,"dcid":"88f2a1554360d01c"}
{"time":1584381670148,"type":"accept","conn":3,"dcid":"7601b689df69c71d"}
{"time":1584381670981,"type":"accept","conn":4,"dcid":"89b4a844beb9ae3f"}
```

## Program Anatomy

h2olog is a [BCC](https://github.com/iovisor/bcc) based C++ program.
It was previously implemented using the [BCC Python binding](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bcc-python).
