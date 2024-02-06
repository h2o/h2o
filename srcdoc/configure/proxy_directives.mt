? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Proxy Directives")->(sub {

<p>
Proxy module is the proxy implementation for H2O - it implements a reverse HTTP proxy and a CONNECT proxy.
</p>
<p>
A reverse HTTP proxy is setup using the <a href="configure/proxy_directives.html#proxy.reverse.url"><code>proxy.reverse.url</code></a> directive.
A CONNECT proxy is setup using the <a href="configure/proxy_directives.html#proxy.reverse.url"><code>proxy.connect</code></a> directive.
</p>
<p>
When acting as a reverse HTTP proxy, following request headers are added and forwarded to the backend server:
<ul>
<li><a href="https://tools.ietf.org/html/rfc7230#section-5.7.1">via</a></li>
<li><a href="http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html#x-forwarded-for">x-forwarded-for</a></li>
<li><a href="http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/x-forwarded-headers.html#x-forwarded-proto">x-forwarded-proto</a></li>
</ul>
</p>
<p>
By default, all requests to the backend server are sent using HTTP/1.1.
Use of HTTP/2 and HTTP/3 to backend servers is considered experimental; their use can be controlled via directives <a href="configure/proxy_directives.html#proxy.http2.ratio"><code>proxy.http2.ratio</code></a> and <a href="configure/proxy_directives.html#proxy.http3.ratio"><code>proxy.http3.ratio</code></a>.
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
    name         => "proxy.connect",
    levels       => [ qw(path) ],
    desc         => q{Setup a CONNECT proxy, taking an access control list as the argument.},
)->(sub {
?>
<p>
Each element of the access control list starts with either <code>+</code> or <code>-</code> followed by an wildcard (<code>*</code>) or an IP address with an optional netmask and an optional port number.
</p>
<p>
When a CONNECT request is received and the name resolution of the connect target is complete, the access control list is searched from top to bottom.
If the first entry that contains a matching address (and optionally the port number) starts with a <code>+</code>, the request is accepted and a tunnel is established.
If the entry starts with a <code>-</code>, the request is rejected.
</p>
<p>
If none of the entries match, the request is also rejected.
</p>
<?= $ctx->{example}->(q{Simple HTTPS proxy}, <<'EOT')
proxy.connect:
- "-192.168.0.0/24"  # reject any attempts to local network
- "+*:443"           # accept attempts to port 443 of any host
EOT
?>
<p>
Note: The precise syntax of the access control list element is <code>address:port/netmask</code>. This is because the URL parser is reused.
</p>
<p>
The directive can only be used for the root path (i.e., <code>/</code>), as the classic CONNECT does not specify the path.
</p>
? })

<?
$ctx->{directive}->(
    name   => "proxy.connect-udp",
    levels => [ qw(path) ],
    desc   => q{Setup a CONNECT-UDP gateway defined by <a href="https://datatracker.ietf.org/doc/rfc9298/" target=_blank>RFC 9298</a>.},
)->(sub {
?>
<p>
Supplied argument is an access control list, using the same format as that of <a href="configure/proxy_directives.html#proxy.connect"><code>proxy.connect</code></a>.
</p>
<p>
Support for draft-03 of the CONNECT-UDP protocol is controlled separately; see <a href="configure/proxy_directives.html#proxy.connect.masque-draft-03"><code>proxy.connect.masque-draft-03</code></a>.
</p>
? })

<?
$ctx->{directive}->(
    name     => "proxy.connect.emit-proxy-status",
    levels   => [ qw(global host path extension) ],
    desc     => q{A boolean flag (<code>ON</code> or <code>OFF</code>) designating if a proxy-status response header should be sent.},
    default  => "proxy.connect.emit-proxy-status: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.proxy-status.identity"><code>proxy.proxy-status.identity</code></a>
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name         => "proxy.connect.masque-draft-03",
    levels       => [ qw(global host path extension) ],
    desc         => q{A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if CONNECT-UDP requests conforming to <a href="https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp/03/" target=_blank>draft-ietf-masque-connect-udp-03</a> should be handled.},
    default      => "proxy.connect.masque-draft-03: OFF",
    experimental => 1,
)->(sub {
?>
<p>
This directive alters the behavior of <a href="configure/proxy_directives.html#proxy.connect"><code>proxy.connect</code></a> because the CONNECT-UDP method defined in draft-03 followed the approach of the CONNECT method, which uses a HTTP proxy as a tunnel.
The published RFC switched to specifying the tunnel by the target URI, and as a result, it is supported by a different directive: <a href="configure/proxy_directives.html#proxy.connect-udp"><code>proxy.connect-udp</code></a>.
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
    desc    => "A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if H2O should add a <code>date</code> header to the response, if that header is missing from the upstream response.",
)->(sub {})
?>

<?
$ctx->{directive}->(
    name    => "proxy.expect",
    levels  => [ qw(global) ],
    since   => "2.3",
    default => q{proxy.expect: OFF},
    desc    => "A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if H2O should send <code>expect: 100-continue</code> header to the request, and postpone sending request body until it receives 100 response",
)->(sub {})
?>

<?
$ctx->{directive}->(
    name    => "proxy.forward.close-connection",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.forward.close-connection: OFF},
    desc    => "A boolean flag indicating if closure of the backend connection should trigger the closure of the frontend HTTP/1.1 connection.",
)->(sub {})
?>

<?
$ctx->{directive}->(
    name    => "proxy.happy-eyeballs.connection-attempt-delay",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.happy-eyeballs.connection-attempt-delay: 250},
    desc    => "<code>Connection Attempt Delay</code> parameter of Happy Eyeballs v2.",
)->(sub {
?>
<p>
When trying to establish a connection to the CONNECT target, H2O uses <a href="https://www.rfc-editor.org/rfc/rfc8305" target=_blank>Happy Eyeballs v2 (RFC 8305)</a>.
This parameter controls the <code>Connection Attempt Delay</code> parameter of Happy Eyeballs v2 in the unit of milliseconds.
</p>
<p>
At the moment, Happy Eyeballs is used only when acting as a CONNECT proxy.
It is not used when running as an HTTP reverse proxy.
</p>
? })

<?
$ctx->{directive}->(
    name    => "proxy.happy-eyeballs.name-resolution-delay",
    levels  => [ qw(global host path extension) ],
    default => q{proxy.happy-eyeballs.name-resolution-delay: 50},
    desc    => "<code>Name Resolution Delay</code> parameter of Happy Eyeballs v2.",
)->(sub {
?>
<p>
For detail, see <a href="configure/proxy_directives.html#proxy.happy-eyeballs.connection-attempt-delay">proxy.happy-eyeballs.connection-attempt-delay</a>.
</p>
? })


<?
for my $action (qw(add append merge set setifempty unset unsetunless)) {
    $ctx->{directive}->(
        name    => "proxy.header.$action",
        levels  => [ qw(global host path extension) ],
        since   => "2.2",
        desc    => "Modifies the request headers sent to the application server.",
    )->(sub {
?>
<p>
The behavior is identical to <a href="configure/headers_directives.html#header.<?= $action ?>"><code>header.<?= $action ?></code></a> except for the fact that it affects the request headers sent to the application server rather than the response headers sent to the client.
Please refer to the documentation of the <a href="configure/headers_directives.html">headers handler</a> to see how the directives can be used to mangle the headers.
</p>
<?
    });
}
?>

<?
$ctx->{directive}->(
    name     => "proxy.header.cookie.unset",
    levels   => [ qw(global host path extension) ],
    desc     => q{Removes cookies in the requests with given name.},
    see_also => render_mt(<<EOT),
<a href="configure/headers_directives.html#header.unset"><code>header.unset</code>/a>
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name     => "proxy.header.cookie.unsetunless",
    levels   => [ qw(global host path extension) ],
    desc     => q{Removes all cookies in the requests but those with given names.},
    see_also => render_mt(<<EOT),
<a href="configure/headers_directives.html#header.unsetunless"><code>header.unsetunless</code></a>
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "proxy.http2.force-cleartext",
    levels  => [ qw(global host path extension) ],
    desc    => q{See <a href="configure/proxy_directives.html#proxy.http2.ratio"><code>proxy.http2.ratio</code></a>.},
    default => "proxy.http2.force-cleartext: OFF",
)->(sub {
?>
? });

<?
$ctx->{directive}->(
    name     => "proxy.http2.max-concurrent-streams",
    levels   => [ qw(global host path extension) ],
    desc     => q{Maxium number of concurrent requests issuable on one HTTP/2 connection to the backend server.},
    default  => "proxy.http2.max-concurrent-streams: 100",
    see_also => render_mt(<<EOT),
<a href="configure/proxy_directives.html#proxy.http2.ratio"><code>proxy.http2.ratio</code></a>
EOT
)->(sub {
?>
<p>
Actual number of maximum requests inflight will be capped to the minimum of this setting and the value advertised in the HTTP/2 SETTINGS frame of the bakend server.
</p>
? });

<?
$ctx->{directive}->(
    name         => "proxy.http2.ratio",
    levels       => [ qw(global host path extension) ],
    desc         => q{Ratio of forwarded HTTP requests with which use of HTTP/2 should be attempted.},
    default      => "proxy.http2.ratio: 0",
    experimental => 1,
)->(sub {
?>
<p>
When the backend protocol is HTTPS, for given ratio of HTTP requests, h2o will either attempt to create or reuse an existing HTTP/2 connection.
Connection attempts to use HTTP/2 will be indicated to the server via ALPN, with fallback to HTTP/1.1.
</p>
<p>
When the backend protocol is cleartext HTTP, this directive has impact only when the ratio is set to <code>100</code> with <a href="configure/proxy_directives.html#proxy.http2.force-cleartext"><code>proxy.http2.force-cleartext</code></a> set to <code>ON</code>. In such case, all backend connection will use HTTP/2 without negotiation.
</p>
? })

<?
$ctx->{directive}->(
    name         => "proxy.http3.ratio",
    levels       => [ qw(global host path extension) ],
    desc         => q{Ratio of forwarded HTTP requests with which use of HTTP/3 should be attempted.},
    default      => "proxy.http3.ratio: 0",
    experimental => 1,
)->(sub {
?>
<p>
When the backend protocol is HTTPS, for given ratio of HTTP requests, h2o will either attempt to create or reuse an existing HTTP/3 connection.
</p>
<p>
When the backend protocol is cleartext HTTP, this directive has no impact.
</p>
? })

<?
$ctx->{directive}->(
    name     => "proxy.max-buffer-size",
    levels   => [ qw(global host path extension) ],
    desc     => q{This setting specifies the maximum amount of userspace memory / disk space used for buffering each HTTP response being forwarded, in the unit of bytes.},
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#temp-buffer-threshold"><code>temp-buffer-threshold</code></a>
EOT
)->(sub {
?>
<p>
By default, h2o buffers unlimited amount of data being sent from backend servers.
The intention behind this approach is to free up backend connections as soon as possible, under the assumption that the backend server might have lower concurrency limits than h2o.
But if the backend server has enough concurrency, <code>proxy.max-buffer-size</code> can be used to restrict the memory / disk pressure caused by h2o at the cost of having more connections to the backend server.
</p>
? })

<?
$ctx->{directive}->(
    name     => "proxy.max-spare-pipes",
    levels   => [ qw(global) ],
    desc     => q{This setting specifies the maximum number of pipes retained for reuse, when <code>proxy.zerocopy</code> is used.},
    default  => 0,
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.zerocopy"><code>proxy.zerocopy</code></a>
EOT
)->(sub {
?>
<p>
This maximum is applied per each worker thread.
The intention of this setting is to reduce lock contention in the kernel under high load when zerocopy is used.
When this setting is set to a non-zero value, specified number of pipes will be allocated upon startup for each worker thread.
</p>
<p>
Setting this value to 0 will cause no pipes to be retained by h2o; the pipes will be closed after they are used.
In this case, h2o will create new pipes each time they are needed.
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
    name    => "proxy.proxy-status.identity",
    levels  => [ qw(global host path extension) ],
    desc    => "Specifies the name of the server to be emitted as part of the <code>proxy-status</code> header field.",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.connect.proxy-status"><code>proxy.connect.proxy-status</code></a>
EOT
)->(sub {});
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
    desc    => q{Sets the upstream I/O timeout in milliseconds.},
)->(sub {
?>
<p>This value will be used for <code>proxy.timeout.connect</code> and <code>proxy.timeout.first_byte</code> as well, unless these parameters are explicitely set.</p>
<?
});
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
    name         => "proxy.tunnel",
    levels       => [ qw(global host path extension) ],
    default      => q{proxy.tunnel: OFF},
    desc         => q{A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not to allow tunnelling to the backend server.},
    experimental => 1,
)->(sub {
?>
<p>
When set to <code>ON</code>, CONNECT requests and <a href="https://tools.ietf.org/html/rfc6455">WebSocket</a> handshakes are forwarded to the backend server.
Then, if the backend server accepts those requests, H2O forwards the HTTP response to the client and acts as a bi-directional tunnel.
</p>
<p>
Timeouts are governed by properties <code>proxy.timeout.connect</code> and <code>proxy.timeout.io</code>.
</p>
? })

<?
$ctx->{directive}->(
    name         => "proxy.zerocopy",
    levels       => [ qw(global) ],
    default      => q{proxy.zerocopy: OFF},
    desc         => q{Sets the use of zerocopy operations for forwarding the response body.},
    experimental => 1,
    see_also     => render_mt(<<'EOT'),
<a href="configure/base_directives.html#ssl-offload"><code>ssl-offload</code></a>, <a href="configure/proxy_directives.html#proxy.max-spare-pipes"><code>proxy.max-spare-pipes</code></a>
EOT
)->(sub {
?>
<p>
By default, this flag is set to <code>OFF</code>, in which case the response bytes are read from the upstream socket to an internal buffer as they arrive, then shipped to the client.
Maximum size of this buffer is controlled by <code>proxy.max-buffer-size</code>.
The drawback of this approach is that it causes pressure on memory bandwidth.
</p>
<p>
This knob provides two alternative modes to remedy the pressure:
</p>
<p>
When set to <code>enabled</code>, if zerocopy operation in supported by the downstream connection (i.e., downstream connection being cleoartext or encrypted using kernel TLS), h2o uses a pipe as an internal buffer instead of using userspace memory.
Data is moved to the pipe using the <code>splice</code> system call, then shipped to the downstream connection by another call to <code>splice</code>.
Pressure to memory bandwidth is eliminated, as the <code>splice</code> system call merely moves the references to kernel memory between file descriptors.
</p>
<p>
When set to <code>always</code>, data from upstream is spliced into a pipe regardless of downstream connection providing support for zerocopy.
When the downstream connection does not support zerocopy, data is intially moved into the pipe, then gets read and written to the socket (as well as being encrypted, if necessary) as late as it becomes possible to send the data.
This approach does not reduce the total amount of bytes flowing through the CPU, but reduces the amount of userspace memory used by h2o by delaying the reads, thereby reducing cache spills.
</p>
? })

? })

? })
