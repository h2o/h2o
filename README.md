# h2olog

[BPF](https://www.kernel.org/doc/html/latest/bpf/index.html) ([kernel doc](https://www.kernel.org/doc/Documentation/networking/filter.txt)) backed request logging client for the [H2O](https://github.com/h2o/h2o) server.

## Quickstart

```
$ h2olog -p $(pgrep -o h2o)
```
