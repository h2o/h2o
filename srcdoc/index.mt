? my $note = $main::context->{note};
? $_mt->wrapper_file("wrapper.mt")->(sub {

<div style="margin-top: 3em;">
<p>
H2O is a new generation HTTP server <b>providing quicker response to users</b> when compared to older generation of web servers.
The server takes full advantage of HTTP/2 features including prioritized content serving and server push, promising outstanding experience to the visitors of your web site.
<div align="center">
<a href="assets/8mbps100msec-nginx195-h2o150.png" target="_blank"><img src="assets/8mbps100msec-nginx195-h2o150.png" width="400"></a>
</div>
Explanation and other benchmark numbers can be found in the <a href="benchmarks.html">benchmarks</a> page.
<p>

</p>
</div>

<h3 id="key-features">Key Features</h3>

<ul>
<li>HTTP/1.0, HTTP/1.1
<li><a href="configure/http2_directives.html">HTTP/2</a>
<ul>
<li>full support for dependency and weight-based prioritization with <a href="configure/http2_directives.html#http2-reprioritize-blocking-assets">server-side tweaks</a></li>
<li><a href="configure/http2_directives.html#http2-casper">cache-aware server push</a></li>
</ul>
</li>
<li>TCP Fast Open
<li><a href="configure/base_directives.html#listen-ssl">TLS</a>
<ul>
<li>session resumption (standalone &amp; memcached)
<li>session tickets with automatic key rollover
<li>automatic OCSP stapling
<li>forward secrecy &amp; fast AEAD ciphers<?= $note->(q{chacha20-poly1305: see <a href="https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/">Do the ChaCha: better mobile performance with cryptography</a>}) ?></li>
<li>private key protection using privilege separation
</ul>
</li>
<li><a href="configure/file_directives.html">static file serving</a>
<li><a href="configure/fastcgi_directives.html">FastCGI</a>
<li><a href="configure/proxy_directives.html">reverse proxy</a>
<li><a href="configure/mruby_directives.html">scriptable using mruby</a> (Rack-based)
<li>graceful restart and self-upgrade
</ul>

<h3 id="news">News</h3>

<ul>
<li>Version <a href="https://github.com/h2o/h2o/releases/tag/v1.5.4">1.5.4</a> is now available with bug fixes (Nov 12 2015)</li>
<li>Version <a href="https://github.com/h2o/h2o/releases/tag/v1.5.3">1.5.3</a> is now available with bug fixes (Nov 6 2015)</li>
<li>Version <a href="https://github.com/h2o/h2o/releases/tag/v1.5.2">1.5.2</a> is now available with bug fixes (Oct 20 2015)</li>
</ul>

<h3 id="security-issues">Security Issues</h3>

<ul>
<li><b><a href="vulnerabilities.html">Security Advisory</a>: one security fix</b> (Sep 16 2015)</li>
</ul>

? })
