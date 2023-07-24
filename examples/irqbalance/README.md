irqbalance
===

irqbalance is a program that aims to minimize traffic across CPU cores, by mapping each incoming connection to a h2o worker thread
running on the CPU core handling interrupts for that connection. 

Launched by h2o through the `connection-mapper` configuration directive, this program receives mappings between CPU cores and the
listening sockets with the SO_REUSEPORT socket option being set. Using this information, the program injects an eBPF sk_reuseport
filter that directs TCP SYN / UDP packets to a SO_REUSEPORT socket pinned to a CPU core on which the interrupt is processed.

Example configuration:

```yaml
num-threads: [0-63]  # launch 64 h2o worker threads pinned to CPU id 0 through 63
tcp-reuseport: ON
connection-mapper: /path/to/irqbalance
```
