? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Proxy Directives")->(sub {

<p>
Proxy module is the reverse proxy implementation for H2O - it implements a HTTP client that forwards a HTTP request to an upstream server.
</p>
<p>
When forwarding the requests, the module sets following request headers:
<ul>
<li><a href="https://tools.ietf.org/html/rfc7230#section-5.7.1">via</a></li>
<li><a href="http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html#x-forwarded-for">x-forwarded-for</a></li>
<li><a href="http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html#x-forwarded-proto">x-forwarded-proto</a></li>
</ul>
</p>
<p>
The HTTP client only supports HTTP/1.
Support for HTTPS has been introduced in version 2.0.
</p>
<p>
Following sections describe the configuration directives defined for the module.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name    => "proxy.reverse.url",
    levels  => [ qw(path) ],
    desc    => q{Forwards the requests to the specified backends, and proxies the response.},
)->(sub {
?>
<?= $ctx->{example}->(q{Forwarding the requests to application server running on <code>127.0.0.1:8080</code>}, <<'EOT')
proxy.reverse.url: "http://127.0.0.1:8080/"
EOT
?>
<?= $ctx->{example}->(q{Forwarding the requests to multiple application server with different weight}, <<'EOT')
proxy.reverse.url:
  - http://10.0.0.1:8080/
  - url: http://10.0.0.2:8080/different-path
    weight: 2
EOT
?>
<?= $ctx->{example}->(q{Forwarding the requests to multiple application server with least connection}, <<'EOT')
proxy.reverse.url:
  backends:
    - http://10.0.0.1:8080/
    - http://10.0.0.2:8080/
  balancer: least-conn
EOT
?>
<p>
When more than one backend is declared, the load is distributed among the backends using the strategy specified by the <code>balancer</code> property.
Currently we support <code>round-robin</code> (the default) and <code>least-conn</code> as the value of the property.
The strategies are applied when establishing a new connection becomes necessary (i.e. when no pooled connections exist).
</p>
<p>
<code>weight</code> can be assigned to each backend as an integer between 1 and 256.
The default value is 1.
</p>
<p>
For the <code>round-robin</code> balancer, <code>weight</code> is respected in this way: each backend would be selected exactly <code>weight</code> times before next backend would be selected, except when the backend is not accessable.
</p>
<p>
For <code>least-conn</code> balancer, <code>weight</code> is respected in this way: the selected backend should have the minimum value of (request count) / (<code>weight</code>).
</p>
<p>
H2O will try to reconnect to different backends (in the order determined by the load balancing strategy) until it successfully establishes a connection.
It returns an error when it fails to connect to all of the backends.
</p>
<p>
In addition to TCP/IP over IPv4 and IPv6, the proxy handler can also connect to an HTTP server listening to a Unix socket.
Path to the unix socket should be surrounded by square brackets, and prefixed with <code>unix:</code> (e.g. <code>http://[unix:/path/to/socket]/path</code>).
</p>

? })

<?
$ctx->{directive}->(
    name    => "proxy.preserve-host",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.preserve-host: OFF},
    desc    => q{A boolean flag (<code>ON</code> or <code>OFF</code>) designating whether or not to pass <code>Host</code> header from incoming request to upstream.},
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "proxy.preserve-x-forwarded-proto",
    levels  => [ qw(global) ],
    since   => "2.0",
    default => q{proxy.preserve-x-forwarded-proto: OFF},
    desc    => "A boolean flag(<code>ON</code> or <code>OFF</code>) indicating if the server preserve the received <code>x-forwarded-proto</code> request header.",
)->(sub {
?>
<p>
By default, when transmitting a HTTP request to an upstream HTTP server, H2O removes the received <code>x-forwarded-proto</code> request header and sends its own, as a precaution measure to prevent an attacker connecting through HTTP to lie that they are connected via HTTPS.
However in case H2O is run behind a trusted HTTPS proxy, such protection might not be desirable, and this configuration directive can be used to modify the behaviour.
</p>
? })

<?
$ctx->{directive}->(
    name     => "proxy.proxy-protocol",
    levels   => [ qw(global host path extension) ],
    since    => "2.1",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.timeout.keepalive"><code>proxy.timeout.keepalive</code></a>
EOT
    default  => q{proxy.proxy-protocol: OFF},
    desc     => q{A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if <a href="http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt" target="_blank">PROXY protocol</a> should be used when connecting to the application server.},
)->(sub {
?>
<p>
When using the PROXY protocol, connections to the application server cannot be persistent (i.e. <a href="configure/proxy_directives.html#proxy.timeout.keepalive"><code>proxy.timeout.keepalive</code></a> must be set to zero).
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.emit-x-forwarded-headers",
    levels  => [ qw(global) ],
    since   => "2.1",
    default => q{proxy.emit-x-forwarded-headers: ON},
    desc    => "A boolean flag(<code>ON</code> or <code>OFF</code>) indicating if the server will append or add the <code>x-forwarded-proto</code> and <code>x-forwarded-for</code> request headers.",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.emit-via-header"><code>proxy.emit-via-header</code></a>
EOT
)->(sub {
?>
<p>
By default, when forwarding an HTTP request H2O sends its own <code>x-forwarded-proto</code> and <code>x-forwarded-for</code> request headers (or might append its value in the <code>x-forwarded-proto</code> case, see <code>proxy.preserve-x-forwarded-proto</code>). This might not be always desirable. Please keep in mind security implications when setting this of <code>OFF</code>, since it might allow an attacker to spoof the originator or the protocol of a request.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.emit-via-header",
    levels  => [ qw(global) ],
    since   => "2.2",
    default => q{proxy.emit-via-header: ON},
    desc    => "A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server adds or appends an entry to the <code>via</code> request header.",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.emit-x-forwarded-headers"><code>proxy.emit-x-forwarded-headers</code></a>
EOT
)->(sub {})
?>

<?
$ctx->{directive}->(
    name    => "proxy.emit-missing-date-header",
    levels  => [ qw(global) ],
    since   => "2.3",
    default => q{proxy.emit-missing-date-header: ON},
    desc    => "A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if H2O should add a <code>date</date> header to the response, if that header is missing from the upstream response.",
)->(sub {})
?>

<?
for my $action (qw(add append merge set setifempty unset)) {
    $ctx->{directive}->(
        name    => "proxy.header.$action",
        levels  => [ qw(global host path extensions) ],
        since   => "2.2",
        desc    => "Modifies the request headers sent to the application server.",
    )->(sub {
?>
<p>
The behavior is identical to <a href="configure/headers_directives.html#header.<?= $action ?>"><code>header.<?= $action ?></code></a> except for the fact that it affects the request sent to the application server.
Please refer to the documentation of the <a href="configure/headers_directives.html">headers handler</a> to see how the directives can be used to mangle the headers.
</p>
<?
    });
}
?>

<?
$ctx->{directive}->(
    name    => "proxy.ssl.cafile",
    levels  => [ qw(global host path extension) ],
    since   => "2.0",
    desc    => "Specifies the file storing the list of trusted root certificates.",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.ssl.verify-peer"><code>proxy.ssl.verify-peer</code></a>
EOT
)->(sub {
?>
<p>
By default, H2O uses <code>share/h2o/ca-bundle.crt</code>.  The file contains a set of trusted root certificates maintained by Mozilla, downloaded and converted using <a href="https://curl.haxx.se/docs/mk-ca-bundle.html">mk-ca-bundle.pl</a>.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.ssl.session-cache",
    levels  => [ qw(global host path extension) ],
    since   => "2.1",
    default => "proxy.ssl.session-cache: ON",
    desc    => "Specifies whether if and how a session cache should be used for TLS connections to the application server.",
)->(sub {
?>
<p>
Since version 2.1, result of the TLS handshakes to the application server is memoized and later used to resume the connection, unless set to <code>OFF</code> using this directive.
If the value is a mapping, then the following two attributes must be specified:
<dl>
<dt>lifetime:</dt>
<dd>validity of session cache entries in seconds</dd>
<dt>capacity:</dt>
<dd>maxmum number of entries to be kept in the session cache</dd>
</dl>
If set to <code>ON</code>, <code>lifetime</code> and <code>capacity</code> will be set to 86,400 (one day) and 4,096.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.ssl.verify-peer",
    levels  => [ qw(global host path extension) ],
    since   => "2.0",
    desc    => "A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server certificate and hostname should be verified.",
    default => q{proxy.ssl.verify-peer: ON},
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.ssl.cafile"><code>proxy.ssl.cafile</code></a>
EOT
)->(sub {
?>
<p>
If set to <code>ON</code>, the HTTP client implementation of H2O verifies the peer's certificate using the list of trusted certificates as well as compares the hostname presented in the certificate against the connecting hostname.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.timeout.io",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.io: 30000},
    desc    => q{Sets the upstream I/O timeout in milliseconds.},
)->(sub {
?>
<p>This value will be used for <code>proxy.timeout.connect</code> and <code>proxy.timeout.first_byte</code> as well, unless these parameters are explicitely set.</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.timeout.connect",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.connect: 30000},
    since   => "2.3",
    desc    => q{Sets the timeout before establishing the upstream in milliseconds.},
)->(sub {
?>
<p>When connecting to a TLS upstream, this timeout will run until the end of the SSL handshake.</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.timeout.first_byte",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.first_byte: 30000},
    since   => "2.3",
    desc    => q{Sets the timeout before receiving the first byte from upstream.},
)->(sub {
?>
<p>This sets the maxium time we will wait for the first byte from upstream, after the establishment of the connection.</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.timeout.io",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.io: 30000},
    since   => "2.3",
    desc    => q{Sets the upstream I/O timeout in milliseconds.},
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "proxy.timeout.keepalive",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.timeout.keepalive: 2000},
    desc    => 'Sets the upstream timeout for idle connections in milliseconds.',
)->(sub {
?>
<p>
Upstream connection becomes non-persistent if the value is set to zero.
The value should be set to something smaller than that being set at the upstream server.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.tunnel",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.tunnel: OFF},
    desc    => q{A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not to allow tunnelling to the backend server.},
)->(sub {
?>
<p>
When set to <code>ON</code>, CONNECT requests and <a href="https://tools.ietf.org/html/rfc6455">WebSocket</a> handshakes are forwarded to the backend server.
Then, if the backend server accepts those requests, H2O forwards the HTTP response to the client and acts as a bi-directional tunnel.
</p>
<p>
Support for tunnelling is considered experimental for the time being and therefore is not yet turned on by default.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.tunnel.timeout",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.websocket.timeout: 300000},
    desc    => q{Sets the idle timeout of a tunnel.},
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.tunnel"><code>proxy.tunnel</code></a>
EOT
)->(sub {})
?>

? })

? })
