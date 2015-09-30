? my $note = $main::context->{note};
? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Benchmarks")->(sub {

<h3 id="download-timings">Download Timings Benchmark</h3>

<div>
<p>
Providing quick response to user is more important than anything else in web performance tuning.
According to a research conducted by Microsoft, 500msec slowdown in Bing causes their revenue go down by 1.2%<?= $note->(q{<a href="http://radar.oreilly.com/2009/07/velocity-making-your-site-fast.html">Velocity and the Bottom Line - O'Reilly Radar</a>}) ?>.
</p>
<p>
The chart below compares the first-paint times and download completion times of different web browsers / HTTP servers on a simulated network of 8Mbps bandwidth with 100ms latency, which is typcial for today's mobile networks<?= $note->(q{<a href="https://github.com/kazuho/http2rulez.com">a fork of http2rulez.com</a> was used as the target website; bandwidth and latency were induced to local network using <a href="http://linux-ip.net/articles/Traffic-Control-HOWTO/components.html">qdisc</a>, specifically by running <code>tc qdisc replace dev eth1 root handle 1:0 tbf rate 8192kbit burst 2048 latency 100ms; sudo tc qdisc add dev eth1 parent 1:1 netem delay 100ms</code>, and <code>sysctl -w net.ipv4.tcp_no_metrics_save=1</code>.}) ?>.
</p>
<div align="center">
<a href="assets/8mbps100msec-nginx195-h2o150.png" target="_blank"><img src="assets/8mbps100msec-nginx195-h2o150.png" width="400"></a>
</div>
<p>
It is clear in the case of this benchmark that the visitors of the web site would be more satisfied, if H2O was used as the HTTP server.
</p>
</div>

<h3 id="remote">Remote Benchmark</h3>

<div>
<p>
Below chart shows the scores recorded on Amazon EC2 running two c3.8xlarge instances (server and client) on a single network placement<?= $note->("for reverse-proxy tests, another H2O process running on the same host was used as the upstream server") ?>.
</p>
<div align="center">
<a href="assets/remotebench.png" target="_blank"><img src="assets/remotebench.png" width="400"></a>
</div>
</div>

<h3 id="local">Local Benchmarks</h3>

<div>
<p>
The scores (requests/second.core) were recorded on Ubuntu 14.04 (x86-64) / VMware Fusion 7.1.0 / OS X 10.9.5 / MacBook Pro 15" Early 2013.
</p>

<table>
<caption>HTTP/1.1<?= $note->(q{used command: <code><a href="https://github.com/wg/wrk">wrk</a> -c 500 -d 30 -t 1</code>; configuration file of nginx is <a href="https://gist.github.com/kazuho/c9c12021567e3ab83809">here</a>}) ?></caption>
<tr><th>Server \ size of content<th>6 bytes<th>4,096 bytes
<tr><td>h2o/0.9.0<td align="right">75,483<td align="right">59,673
<tr><td><a href="http://nginx.org/">nginx</a>/1.7.9<td align="right">37,289<td align="right">43,988
</table>

<table>
<caption>HTTP/2<?= $note->(q{used command: <code><a href="https://github.com/tatsuhiro-t/nghttp2/">h2load</a> -c 500 -m 100 -n 2000000</code>; configuration file of h2o is <a href="https://gist.github.com/kazuho/5966cafb40e4473a62f8">here</a>}) ?></caption>
<tr><th>Server \ size of content<th>6 bytes<th>4,096 bytes
<tr><td>h2o/0.9.0<td align="right">272,300<td align="right">116,022
<tr><td>tiny-nghttpd (<a href="https://github.com/tatsuhiro-t/nghttp2/">nghttpd</a>@ab1dd11)<td align="right">198,018<td align="right">93,868
<tr><td><a href="https://github.com/matsumoto-r/trusterd">trusterd</a>@cff8e15<td align="right">167,306<td align="right">67,600
</table>

</div>

? })
