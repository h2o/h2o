# h2olog

[BPF](https://www.kernel.org/doc/html/latest/bpf/index.html) ([kernel doc](https://www.kernel.org/doc/Documentation/networking/filter.txt)) backed request logging client for the [H2O](https://github.com/h2o/h2o) server.
h2olog can also log [QUIC](https://en.wikipedia.org/wiki/QUIC) events for [transport layer](https://en.wikipedia.org/wiki/Transport_layer) observation.

## Quickstart

Root privilege is required to interact with the BPF virtual machine.
The log line format is: `ConnID ReqID HeaderName HeaderValue`, except the first line that represents the HTTP protocol version.

```
$ sudo h2olog -p $(pgrep -o h2o)

888 1 RxProtocol HTTP/2.0
888 1 RxHeader   :authority torumk.com
888 1 RxHeader   :method GET
888 1 RxHeader   :path /
888 1 RxHeader   :scheme https
888 1 TxStatus   200
... and more ...
```

## Requirements

- Root privilege to execute the program
- H2O server built after [53e1db42](https://github.com/h2o/h2o/commit/53e1db428772460534191d1c35c79a6dd94e021f)
- [BCC](https://iovisor.github.io/bcc/) (BPF Compiler Collection) [installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system
  - BCC v0.11.0 or later is required
  - Note that the bcc module on PyPi is unrelated to BPF.

## Tracing QUIC events

Server-side [QUIC](https://en.wikipedia.org/wiki/QUIC) events can be traced using the `quic` subcommand.
Events are rendered in [JSON](https://en.wikipedia.org/wiki/JSON) format.
This feature is heavily a [WIP](https://en.wikipedia.org/wiki/Work_in_process).

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

h2olog is a [BCC](https://github.com/iovisor/bcc) based single-file [Python](https://www.python.org/) program ([learn more](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bcc-python)).
This might change in the future (e.g. switch to [bpftrace](https://github.com/iovisor/bpftrace)), but the same CLI interface will be kept.

## TODO

- Option for output filtering
- Option to redirect the output to a file
