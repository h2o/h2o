? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/2 Directives")->(sub {

<p>
This document describes the configuration directives for controlling the HTTP/2 protocol handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "http2-idle-timeout",
    levels  => [ qw(global) ],
    default => 'http2-idle-timeout: 10',
    desc    => <<'EOT',
Timeout for idle connections in seconds.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "http2-max-concurrent-requests-per-connection",
    levels  => [ qw(global) ],
    default => 'http2-max-concurrent-requests-per-connection: 256',
    desc    => <<'EOT',
Maximum number of requests to be handled concurrently within a single HTTP/2 connection.
The value cannot exceed 256.
EOT
}) ?>

? })
