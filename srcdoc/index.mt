? my $note = $main::context->{note};
? $_mt->wrapper_file("wrapper.mt")->(sub {

<h2>About H2O</h2>

<div>
H2O is a new generation HTTP server <b>providing quicker response to users</b> when compared to older generation of web servers.

Written in C, can also be <a href="faq.html#libh2o">used as a library</a>.
</div>

<h3>Key Features</h3>

<ul>
<li>HTTP/1.0, HTTP/1.1
<ul>
<li>uses <a href="https://github.com/h2o/picohttpparser/">PicoHTTPParser</a></li>
</ul>
</li>
<li><a href="http://http2.github.io/">HTTP/2</a>
<ul>
<li>supports the final version<?= $note->("also supports draft 14 and 16 for compatibility") ?></li>
<li>negotiation methods: NPN, ALPN, Upgrade, direct</li>
<li>dependency and weight-based prioritization, with tweaks for Google Chrome</li>
<li>server push</li>
</ul>
</li>
<li>WebSocket<?= $note->("only usable at library level") ?></li>
<li>TCP Fast Open
<li>TLS
<ul>
<li>forward secrecy, session resumption and session tickets (both sharable using Memcached)<?= $note->(q{ref: <a href="http://blog.kazuhooku.com/2015/07/h2o-version-140-released-with.html">H2O version 1.4.0 released with outstanding support for forward secrecy and load balancing (and the experimental mruby handler) </a>}) ?></li>
<li>AEAD ciphers including chacha20-poly1305; the cipher preferred by Google Chrome for Android<?= $note->(q{ref: <a href="https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/">Do the ChaCha: better mobile performance with cryptography</a>}) ?></li>
<li>OCSP stapling<?= $note->("automatically enabled") ?></li>
</ul>
</li>
<li>static file serving
<ul>
<li>conditional GETs and range requests
<li>directory listing
<li>mime-type configuration
</ul>
</li>
<li>FastCGI
<ul>
<li>path-based and extension-based configuration
<li>starts / stops the process manager automatically
</ul>
<li>reverse proxy
<ul>
<li>HTTP/1.x only<?= $note->("HTTPS is not supported") ?></li>
<li>persistent upstream connection with hostname lookups</li>
</ul>
</li>
<li>URL rewriting
<ul>
<li>delegation-based (no need to use regular expressions)
<li>recognizes <code>X-Reproxy-URL</code> header sent by web applications
</ul>
<li>access-logging
<ul>
<li>apache-like format strings</li>
</ul>
</li>
<li>graceful restart and self-upgrade</li>
</ul>

<h3>Benchmark</h3>

<h4>First-paint Time Benchmark</h4>

<div>
<p>
First-paint time (time spent until the web browser starts rendering the new page) is an important metric in web-site performance.
The metric is becoming even more important as access from mobile networks become the majority, due to its latency and narrow bandwidth.
</p>
<p>
The chart below compares the first-paint times of different web browsers / HTTP servers on network with latency of 100 milliseconds (typical for 4G mobile network).
H2O reduces the time by a large margin, by fully implementing the prioritization logic defined by HTTP/2 and with tweaks to adjust the behavior of the web browsers<?= $note->(q{benchmark details are explained in <a href="http://blog.kazuhooku.com/2015/06/http2-and-h2o-improves-user-experience.html">HTTP/2 (and H2O) improves user experience over HTTP/1.1 or SPDY</a>}) ?>.
</p>
<div align="center">
<a href="assets/firstpaintbench.png" target="_blank"><img src="assets/firstpaintbench.png" width="400"></a>
</div>
</div>

<h4>Remote Benchmark</h4>

<div>
<p>
Below chart shows the scores recorded on Amazon EC2 running two c3.8xlarge instances (server and client) on a single network placement<?= $note->("for reverse-proxy tests, another H2O process running on the same host was used as the upstream server") ?>.
</p>
<div align="center">
<a href="assets/remotebench.png" target="_blank"><img src="assets/remotebench.png" width="400"></a>
</div>
</div>

<h4>Local Benchmarks</h4>

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
