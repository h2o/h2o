? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Reproxy Directives")->(sub {

<p>
This document describes the configuration directives of the reproxy handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "reproxy",
    levels  => [ qw(global host path) ],
    default => q{reproxy: OFF},
    desc    => <<'EOT',
<p>
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server should recognize the <code>X-Reproxy-URL</code> header sent from <a href="configure/proxy_directives.html#proxy.reverse.url">upstream servers</a>.
</p>
<p>
If H2O recognizes the header, it fetches the contents of the resource specified by the header, and sends the contents as the response to the client.
</p>
<p>For example, an upstream server may send an URL pointing to a large image using the <code>X-Reproxy-URL</code> header stored on a distributed file system, and let H2O fetch and return the content to the client, instead of fetching the image by itself.
Doing so would reduce the load on the application server.
</p>
EOT
}) ?>

? })
