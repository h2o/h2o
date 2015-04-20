? my $note = $main::context->{note};
? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>About H2O</h2>

<div>
H2O is a very fast HTTP server written in C. It can also be <a href="libh2o.html">used as a library</a>.
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
<li>AEAD ciphers including the upcoming ones preferred by Google Chrome<?= $note->("chaha20-poly1305") ?></li>
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

<div>
TBD
</div>

?= $main::context->{citations}->()

</div>

? })
