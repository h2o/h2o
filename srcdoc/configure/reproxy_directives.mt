? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Reproxy Directives")->(sub {

<p>
This document describes the configuration directives of the reproxy handler.
</p>

? $ctx->{directive_list}->()->(sub {

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
The reproxy destination may itself redirect the request.
For example, if <code>/app</code> is configured with <a href="configure/file_directives.html#file.dir"><code>file.dir</code></a>, a reproxy to <code>/app</code> triggers a 301 redirect to <code>/app/</code>.
H2O follows this redirect internally, changing a <code>POST</code> request to <code>GET</code>, even if the original reproxy status was 307 or 308.
To avoid the directory redirect, use <code>/app/</code> as the reproxy URL, or use <a href="configure/file_directives.html#file.file"><code>file.file</code></a> to map a path directly to a file.
</p>
<p>
For example, an upstream server may send an URL pointing to a large image using the <code>X-Reproxy-URL</code> header stored on a distributed file system, and let H2O fetch and return the content to the client, instead of fetching the image by itself.
Doing so would reduce the load on the application server.
</p>
? })

? })

? })
