? my $note = $main::context->{note};
? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Benchmarks")->(sub {

<h3 id="download-timings">Download Timings</h3>

<div>
<p>
Providing quick response to user is more important than anything else in web performance tuning.
According to a research conducted by Microsoft, 500msec slowdown in Bing causes their revenue go down by 1.2%<?= $note->(q{<a href="http://radar.oreilly.com/2009/07/velocity-making-your-site-fast.html">Velocity and the Bottom Line - O'Reilly Radar</a>}) ?>.
</p>
<p>
The chart below compares the first-paint times and download completion times of different web browsers / HTTP servers on a simulated network of 8Mbps bandwidth with 100ms latency, which is typical for today's mobile networks<?= $note->(q{<a href="https://github.com/kazuho/http2rulez.com">A fork of http2rulez.com</a> was used as the target website; bandwidth and latency were induced to local network using <a href="http://linux-ip.net/articles/Traffic-Control-HOWTO/components.html">qdisc</a>, specifically by running <code>tc qdisc replace dev eth1 root handle 1:0 tbf rate 8192kbit burst 2048 latency 100ms; sudo tc qdisc add dev eth1 parent 1:1 netem delay 100ms</code>, and <code>sysctl -w net.ipv4.tcp_no_metrics_save=1</code>.}) ?>.
</p>
<div align="center">
<a href="assets/8mbps100msec-nginx195-h2o150.png" target="_blank"><img src="assets/8mbps100msec-nginx195-h2o150.png" height="300"></a>
</div>
<p>
It is clear in the case of this benchmark that the visitors of the web site would be more satisfied, if H2O was used as the HTTP server.
</p>
</div>

<h3 id="static-file">Static-File Serving</h3>

<div>
<p>
Below chart shows the scores recorded on Amazon EC2 running two c3.8xlarge instances (server and client) on a single network placement, serving a 612-byte file<?= $note->(q{Configuration files used: <a href="https://gist.github.com/kazuho/def1e71281ed4ae07b95">nginx.conf</a>, <a href="https://gist.github.com/kazuho/969bb99bae31d67e01c4">h2o.conf</a>.}) ?>.
For each measurement, 250 concurrent clients were used<?= $note->(q{<a href="https://github.com/wg/wrk">Wrk</a> was used for HTTP/1 tests. <a href="https://nghttp2.org/documentation/h2load-howto.html">h2load</a> was used for HTTP/2.}) ?>.
<code>open_file_cache</code> was used for Nginx.
H2O implements a open-file-cache that gets updated immediately when the files are replaced.
</p>
<div align="center">
<a href="assets/staticfile612-nginx1910-h2o170.png" target="_blank"><img src="assets/staticfile612-nginx1910-h2o170.png" height="300"></a>
</div>
</div>

<h3 id="reverse-proxy">Reverse Proxy</h3>

<div>
<p>
Presented below is an old chart showing the scores recorded on Amazon EC2 running two c3.8xlarge instances (server and client) on a single network placement<?= $note->("For reverse-proxy tests, another H2O process running on the same host was used as the upstream server") ?><?= $note->("open-file-cache was not used in the static-file benchmark") ?>.
</p>
<div align="center">
<a href="assets/remotebench.png" target="_blank"><img src="assets/remotebench.png" width="400"></a>
</div>
</div>

? })
