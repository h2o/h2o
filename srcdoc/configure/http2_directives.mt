? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/2 Directives")->(sub {

<p>
This document describes the configuration directives for controlling the HTTP/2 protocol handler.
</p>

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
<li>if the client does not use dependency-based prioritization, send the contents with their type marked as <code>highest</code> before any other responses
</ul>
</p>
<p>
By default, <code>.css</code> and <code>.js</code> files are given <code>highest</code> priority.
The <a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a> directive should be used to change the priorities associated to content-types and/or extensions.
</p>
? });

? })
