? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Reproxy Directives")->(sub {

<p>
This document describes the configuration directives of the reproxy handler.
</p>

<?
$ctx->{directive}->(
    name    => "reproxy",
    levels  => [ qw(global host path extension) ],
    default => q{reproxy: OFF},
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server should recognize the <code>X-Reproxy-URL</code> header sent from <a href="configure/proxy_directives.html#proxy.reverse.url">upstream servers</a>.
EOT
)->(sub {
?>
<p>
If H2O recognizes the header, it fetches the contents of the resource specified by the header, and sends the contents as the response to the client.
If the status code associated with the <code>X-Reproxy-URL</code> header is 307 or 308, then the method of the original request is used to obtain the specified resource.
Otherwise, the request method is changed to <code>GET</code>.
</p>
<p>
For example, an upstream server may send an URL pointing to a large image using the <code>X-Reproxy-URL</code> header stored on a distributed file system, and let H2O fetch and return the content to the client, instead of fetching the image by itself.
Doing so would reduce the load on the application server.
</p>
? })

? })
