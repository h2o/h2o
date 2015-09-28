? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/2 Directives")->(sub {

<p>
H2O provides one of the world's most sophisticated HTTP/2 protocol implementation, with features including:
<ul>
<li>HTTP/2 prioritization
<ul>
<li>proportionally distributes the bandwidth as defined in the <a href="https://httpwg.github.io/specs/rfc7540.html">HTTP/2 specification</a>, for both weight and dependency-based prioritization
<li>mime-type based override for client-based prioritization for even better performance
</ul>
<li>server-push
<ul>
<li>recognizes the <code>Link: rel=preload</code> header set by the <a href="configure/proxy_directives.html">proxy</a>, <a href="configure/fastcgi_directives.html">fastcgi</a>, <a href="configure/mruby_directives.html">mruby</a> handlers
<li>tracks the state of web browser cache, and cancels the push if the client is known to be in possession of the resource
</ul>
</ul>

<p>
The following describes the configuration directives for controlling the HTTP/2 protocol handler.
</p>

<?
$ctx->{directive}->(
    name    => "http2-casper",
    levels  => [ qw(global host) ],
    default => "http2-casper: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>,
<a href="https://github.com/h2o/h2o/issues/421">issue #421</a>
EOT
    desc    => <<'EOT',
Configures CASPer (cache-aware server-push).
EOT
)->(sub {
?>
<p>
When enabled, H2O maintains a fingerprint of the web browser cache, and cancels server-push suggested by the handlers if the client is known to be in possention of the content.
The fingerprint is stored in a cookie named <code>h2o_casper</code> using <a href="https://www.imperialviolet.org/2011/04/29/filters.html">Golomb-compressed sets</a> (a compressed encoding of <a href="https://en.wikipedia.org/wiki/Bloom_filter">Bloom filter</a>).
</p>
<p>
If the value is <code>OFF</code>, the feature is disabled.
Push requests (made by the handlers through the use of <code>Link: rel=preload</code> header) are processed regardless of whether if client already has the responses in its cache.
If the value is <code>ON</code>, the feature is enabled with the defaults value specified below.
If the value is mapping, the feature is enabled, recognizing the following attributes.
<dl>
<dt>capacity-bits:
<dd>number of bits used for the fingerprinting.
Roughly speaking, the number of bits should be <code>log2(1/P * number-of-assets-to-track)</code> where P being the probability of false positives.
Default is <code>13</code>, enough for tracking about 100 asset files with 1/100 chance of false positives (i.e. <code>log2(100 * 100) =~ 2<sup>13</code>).
<dt>tracking-types:
<dd>specifies the types of the content tracked by casper.
If omitted or set to <code>blocking-assets</code>, maintains fingerprint (and cancels server push) for resources with mime-type of <a href="configure/file_directives.html#file.mime.addtypes"><code>highest</code></a> priority.
If set to <code>all</code>, tracks all responses.
</dl>
</p>
It should be noted that the size of the cookie will be <code>log2(P) * number-of-assets-being-tracked</code> bits multiplied by the overhead of Base 64 encoding (<code>4/3</code>).
Therefore with current cookie-based implementation, it is necessary in many cases to restrict the resources being tracked to those have significant effect to user-percieved response time.
</p>

<?= $ctx->{example}->('Enabling CASPer', <<'EOT')
http2-casper: ON

# `ON` is equivalent to:
# http2-casper:
#   capacity-bits:  13
#   tracking-types: blocking-assets
EOT
?>

? });

<?
$ctx->{directive}->(
    name    => "http2-idle-timeout",
    levels  => [ qw(global) ],
    default => 'http2-idle-timeout: 10',
    desc    => <<'EOT',
Timeout for idle connections in seconds.
EOT
)->(sub {});

$ctx->{directive}->(
    name    => "http2-max-concurrent-requests-per-connection",
    levels  => [ qw(global) ],
    default => 'http2-max-concurrent-requests-per-connection: 256',
    desc    => <<'EOT',
Maximum number of requests to be handled concurrently within a single HTTP/2 connection.
EOT
)->(sub {
?>
<p>
The value cannot exceed 256.
</p>
? })

<?
$ctx->{directive}->(
    name    => "http2-reprioritize-blocking-assets",
    levels  => [ qw(global) ],
    default => 'http2-reprioritize-blocking-assets: OFF',
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>,
<a href="http://blog.kazuhooku.com/2015/06/http2-and-h2o-improves-user-experience.html">HTTP/2 (and H2O) improves user experience over HTTP/1.1 or SPDY</a>
EOT
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server should send contents with <code>highest</code> priority before anything else.
EOT
)->(sub {
?>
<p>
To maximize the user-perceived reponsiveness of a web page, it is essential for the web server to send blocking assets (i.e. CSS and JavaScript files in <code>&lt;HEAD&gt;</code>) before any other files such as images.
HTTP/2 provides a way for web browsers to specify such priorities to the web server.
However, as of Sep. 2015, all major web browsers except Mozilla Firefox fail to take advantage of the feature.
</p>
<p>
This option, when enabled, works as a workaround for such web browsers, thereby improving experience of users using the web browsers.
</p>
<p>
Technically speaking, it does the following:
<ul>
<li>if the client uses dependency-based prioritization, do not reprioritize
<li>if the client does not use dependency-based prioritization, send the contents of which their types are given <a href="configure/file_directives.html#file.mime.addtypes"><code>highest</code></a> priority before any other responses
</ul>
</p>
? });

? })
