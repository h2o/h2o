? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/1 Directives")->(sub {

<p>
This document describes the configuration directives for controlling the HTTP/1 protocol handler.
</p>

<?=
$_mt->render_file("directive.mt", {
    name   => "http1-request-timeout",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Timeout for incoming requests in seconds.
Default is 10.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "http1-upgrade-to-http2",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
boolean flag indicating whether or not to allow upgrade to HTTP/2.
The value should either be <code>ON</code> or <code>OFF</code>.
Default is <code>ON</code>
</p>
EOT
}) ?>

? })
