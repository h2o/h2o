? my $note = $main::context->{note};
? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>About H2O</h2>

<div>
H2O is a very fast HTTP server written in C. It can also be <a href="faq.html#libh2o">used as a library</a>.
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
<li>dependency and weight-based prioritization</li>
<li>server push</li>
</ul>
</li>
<li>WebSocket<?= $note->("only usable at library level") ?></li>
<li>TLS
<ul>
<li>uses OpenSSL or LibreSSL</li>
<li>forward secrecy</li>
<li>AEAD ciphers including the upcoming ones preferred by Google Chrome<?= $note->(q{chacha20-poly1305; see also: <a href="https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/">Do the ChaCha: better mobile performance with cryptography</a>}) ?></li>
<li>OCSP stapling<?= $note->("automatically enabled") ?></li>
<li>session resumption and session tickets<?= $note->("internal memory is used as the storage") ?></li>
</ul>
</li>
<li>static file serving
<ul>
<li>conditional GET using last-modified / etag</li>
<li>directory listing</li>
<li>mime-type configuration</li>
</ul>
</li>
<li>reverse proxy
<ul>
<li>HTTP/1.x only<?= $note->("HTTPS is not supported") ?></li>
<li>persistent upstream connection</li>
</ul>
</li>
<li>access-logging
<ul>
<li>apache-like format strings</li>
</ul>
</li>
<li>graceful restart and self-upgrade</li>
</ul>

<h3>Benchmark</h3>

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

?= $_mt->render_file("notes.mt")

</div>

? })
