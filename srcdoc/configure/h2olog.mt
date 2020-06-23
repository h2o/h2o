? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using h2olog for Tracing")->(sub {

<p>h2olog is a <a href="https://www.kernel.org/doc/html/latest/bpf/index.html">BPF</a> (<a href="https://www.kernel.org/doc/Documentation/networking/filter.txt">kernel doc</a>) backed HTTP request tracing tool for the <a href="https://github.com/h2o/h2o">H2O</a> server.
h2olog can also be used to log <a href="https://en.wikipedia.org/wiki/QUIC">QUIC</a> events for <a href="https://en.wikipedia.org/wiki/Transport_layer">transport layer</a> observation.
See <a href="#tracing-quic-events">Tracing QUIC events</a> for how.</p>

<h2 id="installing-from-source">Installing from Source</h2>

<p>See <a href="#requirements">requirements</a> for build prerequisites. If dependencies are satisfied, <code>-DWITH_H2OLOG=on</code> will be set and the <code>h2olog</code> target will be configured.</p>
<p>If you have <code>BCC</code> installed to a non-standard path, use <code>pkg-config</code> for <code>cmake</code>.

<?= $ctx->{code}->(<<'EOT')
$ PKG_CONFIG_PATH=/path/to/bcc/lib/pkgconfig cmake [options]
EOT
?>

<h2 id="requirements">Requirements</h2>

<h3>For building h2olog</h3>
<ul>
<li>C++11 compiler</li>
<li>CMake for generating the build files</li>
<li>pkg-config for detecting dependencies</li>
<li>Python 3 for the code generator</li>
<li><a href="https://iovisor.github.io/bcc/">BCC (a.k.a. bpfcc)</a>(&gt;= 0.11.0) <a href="https://github.com/iovisor/bcc/blob/master/INSTALL.md">installed</a> on your system</li>
</ul>
<p>For Ubuntu 20.04 or later, you can install dependencies with:</p>
<?= $ctx->{code}->(<<'EOT')
$ sudo apt install clang cmake python3 libbpfcc-dev linux-headers-$(uname -r)
EOT
?>
<h3>For running h2olog</h3>
<ul>
<li>Root privilege to execute the program</li>
<li>Linux kernel (&gt;= 4.9)</li>
<li>H2O server built after <a href="https://github.com/h2o/h2o/commit/53e1db428772460534191d1c35c79a6dd94e021f">53e1db42</a> with <code>-DWITH_DTRACE=on</code> cmake option</li>
</ul>

<h2 id="quicstart">Quickstart</h2>
<p><code>h2olog -p $H2O_PID</code> shows <a href="https://varnish-cache.org/docs/trunk/reference/varnishlog.html">varnishlog</a>-like tracing.</p>

<?= $ctx->{code}->(<<'EOT')
$ sudo h2olog -p $(pgrep -o h2o)

11 0 RxProtocol HTTP/3.0
11 0 RxHeader   :authority torumk.com
11 0 RxHeader   :method GET
11 0 RxHeader   :path /
11 0 RxHeader   :scheme https
11 0 TxStatus   200
11 0 TxHeader   content-length 123
11 0 TxHeader   content-type text/html
... and more ...
EOT
?>

<h2 id="tracing-quic-events">Tracing QUIC events</h2>
<p>Server-side <a href="https://en.wikipedia.org/wiki/QUIC">QUIC</a> events can be traced using the <code>quic</code> subcommand.
Events are rendered in <a href="https://en.wikipedia.org/wiki/JSON">JSON</a> format.</p>

<?= $ctx->{code}->(<<'EOT')
$ sudo h2olog quic -p $(pgrep -o h2o)
              ^
              |_ The quic subcommand
EOT
?>

<p>Here’s an example trace.</p>

<?= $ctx->{code}->(<<'EOT')
{"time":1584380825832,"type":"accept","conn":1,"dcid":"f8aa2066e9c3b3cf"}
{"time":1584380825835,"type":"crypto-decrypt","conn":1,"pn":0,"len":1236}
{"time":1584380825832,"type":"quictrace-recv","conn":1,"pn":0}
{"time":1584380825836,"type":"crypto-handshake","conn":1,"ret":0}
... and more ...
EOT
?>

<h2 id="program-anatomy">Program Anatomy</h2>

<p>h2olog is a <a href="https://github.com/iovisor/bcc">BCC</a> based C++ program.
It was previously implemented using the <a href="https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bcc-python">BCC Python binding</a> on <a href="https://github.com/toru/h2olog">toru/h2olog</a>.</p>

? })
