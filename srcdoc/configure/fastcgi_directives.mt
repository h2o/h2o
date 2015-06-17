? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "FastCGI Directives")->(sub {

<p>
This document describes the configuration directives of the FastCGI handler.
</p>
<p>
The configuration directives of the FastCGI handler can be categorized into two groups.
<code>Fastcgi.connect</code> and <code>fastcgi.spawn</code> define the address (or the process) to which the requests should be sent.
Other directives customize how the connections to the FastCGI processes should be maintained.
</p>

<?
$ctx->{directive}->(
    name      => "fastcgi.connect",
     levels    => [ qw(path extension) ],
     desc      => q{The directive specifies the address at where the FastCGI daemon is running.},
)->(sub {
?>
<p>
If the argument is a scalar, the value is considered as the path to a unix socket.
Following properties are recognized if the argument is a mapping.
<dl>
<dt><code>host</code>
<dd>name (or IP address) of the server running the FastCGI daemon (ignored if <code>type</code> is <code>unix</code>)
<dt><code>port</code>
<dd>TCP port number or path to the unix socket
<dt><code>type</code>
<dd>either <code>tcp</code> (default) or <code>unix</code>
</dl>
</p>
<?= $ctx->{example}->('Map <code>/app</code> to FastCGI daemon listening to <code>/tmp/fcgi.sock</code>', <<'EOT');
hosts:
    "example.com:80":
        paths:
            "/app":
                fastcgi.connect: /tmp/fcgi.sock
EOT
?>
? })

<?
$ctx->{directive}->(
    name      => "fastcgi.spawn",
     levels    => [ qw(path extension) ],
     desc      => q{The directive specifies the command to start the FastCGI process manager.},
)->(sub {
?>
<p>
In contrast to <code>fastcgi.connect</code> that connects to a FastCGI server running externally, this directive launches a FastCGI process manager under the control of H2O, and terminates it when H2O quits.
The argument is a <code>/bin/sh -c</code> expression to be executed when H2O boots up.
The HTTP server records the process id of the expression, and sends <code>SIGTERM</code> to the id when it exits.
</p>
<?= $ctx->{example}->('Map <code>.php</code> files to 10 worker processes of <code>/usr/local/bin/php-cgi</code>', <<'EOT');
file.custom-handler:
    extension:     .php
    fastcgi.spawn: "PHP_FCGI_CHILDREN=10 exec /usr/local/bin/php-cgi"
EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "fastcgi.timeout.io",
    levels  => [ qw(global host path extension) ],
    default => q{fastcgi.timeout.io: 30000},
    desc    => q{Sets the I/O timeout of connections to the FastCGI process in milliseconds.},
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "fastcgi.timeout.keepalive",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.keepalive: 0},
    desc    => 'Sets the keepl-alive timeout for idle connections in milliseconds.',
)->(sub {
?>
<p>
FastCGI connections will not be persistent if the value is set to zero (default).
</p>
? })

<?
$ctx->{directive}->(
    name    => "fastcgi.send-delegated-uri",
    levels  => [ qw(global host path extension) ],
    default => q{fastcgi.send-delegated-uri: OFF},
    desc    => 'Send the modified <code>HTTP_HOST</code> and <code>REQUEST_URI</code> being rewritten in case of internal redirect.',
)->(sub {
?>
<p>
In H2O, it is possible to perform internal redirects (a.k.a. delegations or URL rewrites) using <a href="configure/redirect_directives.html">the <code>redirect</code> directive</a> or <a href="configure/reproxy_directives.html">by returning <code>X-Reproxy-URL</code> headers</a> from web applications.
The directive specifies whether to send the original values to the FastCGI process (default), or if the rewritten values should be sent.
</p>
? })

? })
