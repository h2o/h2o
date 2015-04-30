? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Proxy Directives")->(sub {

<p>
This document describes the configuration directives of the proxy handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "proxy.reverse.url",
    levels  => [ qw(path) ],
    desc    => <<'EOT',
<p>
Forwards the requests to the specified URL, and transfers the response.
At the moment, only HTTP is supported.
</p>
<div class="example">
<div class="caption">Example. Forwarding the requests to application server running on <code>127.0.0.1:8080</code></div>
<pre><code>proxy.reverse.url: "http://127.0.0.1:8080/"</code></pre>
</div>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "proxy.preserve-host",
    levels  => [ qw(global host path) ],
    default => q{proxy.preserve-host: OFF},
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) designating whether or not to pass <code>Host</code> header from incoming request to upstream.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "proxy.timeout.io",
    levels  => [ qw(global host path) ],
    default => q{proxy.timeout.io: 5000},
    desc    => <<'EOT',
Sets the upstream I/O timeout in milliseconds.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "proxy.timeout.keepalive",
    levels  => [ qw(global host path) ],
    default => q{proxy.timeout.keepalive: 2000},
    desc    => <<'EOT',
<p>
Sets the upstream timeout for idle connections in milliseconds.
The value should be set to something smaller than that being set at the upstream server.
</p>
<p>
Upstream connection becomes non-persistent if the value is set to zero.
</p>
EOT
}) ?>

? })
