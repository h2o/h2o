# h2olog

[BPF](https://www.kernel.org/doc/html/latest/bpf/index.html) ([kernel doc](https://www.kernel.org/doc/Documentation/networking/filter.txt)) backed request logging client for the [H2O](https://github.com/h2o/h2o) server.

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

- H2O server built after [53e1db42](https://github.com/h2o/h2o/commit/53e1db428772460534191d1c35c79a6dd94e021f)
- [BCC](https://iovisor.github.io/bcc/) (BPF Compiler Collection) [installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) on your system
  - BCC v0.11.0 or later is required
- Root privilege to execute the program

Note that the bcc module on PyPi is unrelated to BPF.

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
{"at": 1580154303455, "type": "accept", "master_conn_id": 1, "dcid": "4070a82916f79d71"}
{"at": 1580154303457, "type": "packet_prepare", "master_conn_id": 1, "first_octet": 192, "dcid": "9e4605bc54ec8b9d"}
{"at": 1580154303457, "type": "packet_commit", "master_conn_id": 1, "packet_num": 0, "packet_len": 176, "ack_only": 0}
... and more ...
```

If you find the output to be too noisy, try using the `-t` option to only trace a specific event type.

```
$ sudo h2olog quic -t accept -p $(pgrep -o h2o)

{"at": 1580410632750, "type": "accept", "master_conn_id": 2, "dcid": "cf53a37d6f47a005"}
{"at": 1580410633662, "type": "accept", "master_conn_id": 1, "dcid": "180c19519904013e"}
{"at": 1580410636950, "type": "accept", "master_conn_id": 2, "dcid": "8ccc04ffae33cc7b"}
{"at": 1580410637613, "type": "accept", "master_conn_id": 3, "dcid": "1f3b9363a583158b"}
```

## Program Anatomy

h2olog is a [BCC](https://github.com/iovisor/bcc) based single-file [Python](https://www.python.org/) program ([learn more](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bcc-python)).
This might change in the future (e.g. switch to [bpftrace](https://github.com/iovisor/bpftrace)), but the same CLI interface will be kept.

## TODO

- Option for output filtering
- Option to redirect the output to a file
