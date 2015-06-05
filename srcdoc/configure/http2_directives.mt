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
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server should send CSS and JS files above anything else.

EOT
)->(sub {
?>
<p>
This option has a positive impact on first-paint time on Google Chrome.
For more information please refer to <a href="http://blog.kazuhooku.com/2015/06/http2-and-h2o-improves-user-experience.html">HTTP/2 (and H2O) improves user experience over HTTP/1.1 or SPDY</a>.
</p>
? });

? })
