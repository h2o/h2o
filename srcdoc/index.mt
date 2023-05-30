? my $note = $main::context->{note};
? $_mt->wrapper_file("wrapper.mt")->(sub {

<div style="margin-top: 3em;">
<p>
H2O is a new generation HTTP server that <b>provides quicker response to users with less CPU, memory bandwidth utilization</b> when compared to older generation of web servers.
Designed from ground-up, the server implements of <a href="configure/http2_directives.html">HTTP/2</a> and <a href="configure/http3_directives.html">HTTP/3</a> taking the advantages of features including <a href="https://www.rfc-editor.org/rfc/rfc9218.html" target=_blank>new</a> and <a href="configure/http2_directives.html#prioritization">old content prioritization schemes</a>, <a href="configure/http2_directives.html#server-push">server push</a>, <a href="configure/base_directives.html#send-informational">103 Early Hints</a>, promising outstanding experience to the visitors of the web site.
<div align="center">
<a href="assets/8mbps100msec-nginx195-h2o150.png" target="_blank"><img src="assets/8mbps100msec-nginx195-h2o150.png" width="333" height="250"></a>
<a href="assets/staticfile612-nginx1910-h2o170.png" target="_blank"><img src="assets/staticfile612-nginx1910-h2o170.png" width="200" height="250"></a>
</div>
Explanation of the benchmark charts can be found in the <a href="benchmarks.html">benchmarks</a> page.
<p>

</p>
</div>

<h3>Key Features</h3>

<ul>
<li>HTTP/1.0, HTTP/1.1
<li><a href="configure/http2_directives.html">HTTP/2</a>
<ul>
<li>full support for dependency and weight-based prioritization with <a href="configure/http2_directives.html#http2-reprioritize-blocking-assets">server-side tweaks</a></li>
<li><a href="configure/http2_directives.html#http2-casper">cache-aware server push</a></li>
</ul>
</li>
<li><a href="configure/http3_directives.html">HTTP/3</a>
<ul>
<li>full support for Extensible Priorities (<a href="https://www.rfc-editor.org/rfc/rfc9218.html" target=_blank>RFC 9218</a>)</li>
<li><a href="https://github.com/h2o/picotls/pull/310" target=_blank>fusion AES-GCM engine</a> for fast QUIC packet generation</li>
</ul>
<li>TCP
<ul>
<li>TCP Fast Open
<li><a href="configure/http2_directives.html#latency-optimization">low latency tweaks</a>
</ul>
<li><a href="configure/base_directives.html#listen-ssl">TLS</a>
<ul>
<li>session resumption (standalone &amp; memcached)
<li>session tickets with automatic key rollover
<li>automatic OCSP stapling
<li>forward secrecy
<li><a href="configure/base_directives.html#ssl-offload">zerocopy and hardware crypto offloading</a>
<li><a href="configure/base_directives.html#neverbleed">private key protection using privilege separation</a> with support for Intel QuickAssist Technology
</ul>
</li>
<li><a href="configure/file_directives.html">static file serving</a>
<li><a href="configure/fastcgi_directives.html">FastCGI</a>
<li><a href="configure/proxy_directives.html">reverse proxy</a>
<li><a href="configure/mruby.html">scriptable using mruby</a> (Rack-based)
<li>graceful restart and self-upgrade
<li><a href="configure/h2olog.html">BPF-based tracing tool</a> (experimental)</li>
</ul>

? })
