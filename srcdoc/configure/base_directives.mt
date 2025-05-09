? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Base Directives")->(sub {

<p>
This document describes the configuration directives common to all the protocols and handlers.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name   => "hosts",
    levels => [ qw(global) ],
    desc   => q{Maps <code>host:port</code> to the mappings of per-host configs.},
)->(sub {
?>
<p>
The directive specifies the mapping between the authorities (the host or <code>host:port</code> section of an URL) and their configurations.
The directive is mandatory, and must at least contain one entry.
</p>
<p>
When <code>port</code> is omitted, the entry will match the requests targetting the default ports (i.e. port 80 for HTTP, port 443 for HTTPS) with given hostname.
Otherwise, the entry will match the requests targetting the specified port.
</p>
<p>
Since version 1.7, a wildcard character <code>*</code> can be used as the first component of the hostname.
If used, they are matched using the rule defined in <a href="https://tools.ietf.org/html/rfc2818#section-3.1" target="_blank">RFC 2818 Section 3.1</a>.
For example, <code>*.example.com</code> will match HTTP requests for both <code>foo.example.com</code> and <code>bar.example.com</code>.
</p>

<p>
For each HTTP request to be processed, the matching host entry is determined by the steps below:
<ol>
<li>Among the host elements that do not use wildcards, find the first element that matches the host and port being specified by the URI.</li>
<li>If none is found in the previous step, find a matching element among the entries that use wildcards.</li>
<li>If none is found in the previous steps, use the first host element without a <a href="configure/base_directives.html#strict-match"><code>strict-match</code></a> flag.
</ol>
</p>
<p>
When the hostname of the HTTP request is unknown (i.e., processing an HTTP/1.0 request without a host header field), only the last step is being used.
</p>

<?= $ctx->{example}->('A host redirecting all HTTP requests to HTTPS', <<'EOT');
hosts:
  "www.example.com:80":
    listen:
      port: 80
    paths:
      "/":
        redirect: https://www.example.com/
  "www.example.com:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/ssl-key-file
        certificate-file: /path/to/ssl-certificate-file
    paths:
      "/":
        file.dir: /path/to/doc-root
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "paths",
    levels => [ qw(host) ],
    desc   => q{Mapping of paths and their configurations.},
)->(sub {
?>
</p>
<p>
The mapping is searched using prefix-match.
The entry with the longest path is chosen when more than one matching paths were found.
An <code>404 Not Found</code> error is returned if no matching paths were found.
</p>
<?= $ctx->{example}->('Configuration with two paths', <<'EOT')
hosts:
  "www.example.com":
    listen:
      port: 80
    paths:
      "/":
        file.dir: /path/to/doc-root
      "/assets":
        file.dir: /path/to/assets
EOT
?>
<p>
In releases prior to version 2.0, all the path entries are considered as directories.
When H2O receives a request that exactly matches to an entry in paths that does not end with a slash, the server always returns a 301 redirect that appends a slash.
</p>
<p>
Since 2.0, it depends on the handler of the path whether if a 301 redirect that appends a slash is returned.
Server administrators can take advantage of this change to define per-path configurations (see the examples in <a href="configure/file_directives.html#file.file"><code>file.file</code></a> and the <a href="configure/fastcgi_directives.html">FastCGI handler</a>).
<a href="configure/file_directives.html#file.dir"><code>file.dir</code></a> is an exception that continues to perform the redirection; in case of the example above, access to <code>/assets</code> is redirected to <code>/assets/</code>.
</p>
? })

<?
$ctx->{directive}->(
    name   => "listen",
    levels => [ qw(global host) ],
    desc   => q{Specifies the port at which the server should listen to.},
)->(sub {
?>
</p>
<p>
In addition to specifying the port number, it is also possible to designate the bind address or the SSL and HTTP/3 (QUIC) configuration.
</p>
<?= $ctx->{example}->('Various ways of using the Listen Directive', <<'EOT')
# accept HTTP on port 80 on default address (both IPv4 and IPv6)
listen: 80

# accept HTTP on 127.0.0.1:8080
listen:
  host: 127.0.0.1
  port: 8080

# accept HTTPS on port 443
listen:
  port: 443
  ssl:
    key-file: /path/to/key-file
    certificate-file: /path/to/certificate-file

# accept HTTPS on port 443 (using PROXY protocol)
listen:
  port: 443
  ssl:
    key-file: /path/to/key-file
    certificate-file: /path/to/certificate-file
  proxy-protocol: ON
EOT
?>
<p>
To configure HTTP/3 (QUIC), see <a href="configure/http3_directives.html">HTTP/3</a>.
</p>
<h4 id="listen-configuration-levels">Configuration Levels</h4>
<p>
The directive can be used either at global-level or at host-level.
At least one <code>listen</code> directive must exist at the global level, or every <i>host</i>-level configuration must have at least one <code>listen</code> directive.
</p>
<p>
Incoming connections accepted by global-level listeners will be dispatched to one of the host-level contexts with the corresponding <code>host:port</code>, or to the first host-level context if none of the contexts were given <code>host:port</code> corresponding to the request.
</p>
<p>
Host-level listeners specify bind addresses specific to the host-level context.
However it is permitted to specify the same bind address for more than one host-level contexts, in which case hostname-based lookup will be performed between the host contexts that share the address.
The feature is useful for setting up a HTTPS virtual host using <a href="https://tools.ietf.org/html/rfc6066">Server-Name Indication (RFC 6066)</a>.
</p>
<?= $ctx->{example}->('Using host-level listeners for HTTPS virtual-hosting', <<'EOT')
hosts:
  "www.example.com:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_com.key
        certificate-file: /path/to/www_example_com.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_com
  "www.example.jp:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_jp.key
        certificate-file: /path/to/www_example_jp.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_jp
EOT
?>
<h4 id="listen-ssl">SSL Attribute</h4>
<p>
The <code style="font-weight: bold;">ssl</code> attribute must be defined as a mapping, and recognizes the following attributes.
</p>
<dl>
<dt id="certificate-file">certificate-file:</dt>
<dd>
Path of the SSL certificate file (mandatory).
This attribute can specify a PEM file containing either an X.509 certificate chain or a raw public key.
When the latter form is being used, <a href="https://datatracker.ietf.org/doc/html/rfc7250">RFC 7250</a> handshake will be used.
</dd>
<dt id="key-file">key-file:</dt>
<dd>Path of the SSL private key file (mandatory).</dd>
<dt>identity:</dt>
<dd>List of certificate / key pairs.
This attribute can be used in place of <code>certificate-file</code> and <code>key-file</code> to specify more than one pair of certificates and keys.
When a TLS handshake is performed, h2o uses the first pair that contains a compatible certificate / key.
The last pair acts as the fallback.
<?= $ctx->{example}->('Using RSA and ECDSA certificates', <<'EOT')
ssl:
  identity:
  - key-file: /path/to/rsa.key
    certificate-file: /path/to/rsa.crt
  - key-file: /path/to/ecdsa.key
    certificate-file: /path/to/ecdsa.crt
EOT
?>
<dt id="minimum-version">minimum-version:</dt>
<dd>
minimum protocol version, should be one of: <code>SSLv2</code>, <code>SSLv3</code>, <code>TLSv1</code>, <code>TLSv1.1</code>, <code>TLSv1.2</code>, <code>TLSv1.3</code>.
Default is <code>TLSv1</code>.
</dd>
<dt id="min-version">min-version:</dt>
<dd>
synonym of <code>minimum-version</code> (introduced in version 2.2)
</dd>
<dt id="maximum-version">maximum-version:</dt>
<dd>
maximum protocol version.
Introduced in version 2.2.
Default is the maximum protocol version supported by the server.
</dd>
<dt id="maximum-version">max-version:</dt>
<dd>
synonym of <code>maximum-version</code>.
</dd>
<dt id="cipher-suite">cipher-suite:</dt>
<dd>list of cipher suites to be passed to OpenSSL via SSL_CTX_set_cipher_list (optional)</dd>
<dt id="cipher-suite-tls1.3">cipher-suite-tls1.3:</dt>
<dd>list of TLS 1.3 cipher suites to use; the list must be a YAML sequence where each element specifies the cipher suite using the name as registered to the <a href="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4" target=_blank>IANA TLS Cipher Suite Registry</a>; e.g., <code>TLS_AES_128_GCM_SHA256</code>, <code>TLS_CHACHA20_POLY1305_SHA256</code>.
<dt id="cipher-preferences">cipher-preference:</dt>
<dd>
side of the list that should be used for selecting the cipher-suite; should be either of: <code>client</code>, <code>server</code>.
Default is <code>client</code>.
</dd>
<dt id="dh-file">dh-file:</dt>
<dd>
path of a PEM file containing the Diffie-Hellman parameters to be used.
Use of the file is recommended for servers using Diffie-Hellman key agreement.
(optional)
</dd>
<dt id="key-exchange-tls1.3">key-exchange-tls1.3:</dt>
<dd>list of TLS 1.3 key exchange algorithms to use; the list must be a YAML sequence of algorithms. <code>x25519</code> and <code>secp256r1</code> are supported and enabled by default. In addition, <code>secp384r1</code>, <code>secp521r1</code>, and <code>x25519mlkem768</code> might be available if they are supported by libcrypto.</dd>
<dt id="ocsp-update-interval">ocsp-update-interval:</dt>
<dd>
interval for updating the OCSP stapling data (in seconds), or set to zero to disable OCSP stapling.
Default is <code>14400</code> (4 hours).
</dd>
<dt id="ocsp-max-failures">ocsp-max-failures:</dt>
<dd>
number of consecutive OCSP query failures before stopping to send OCSP stapling data to the client.
Default is 3.
</dd>
<dt id="max-tickets">max-tickets:</dt>
<dd>
maximum number of TLS/1.3 session tickets to send, when the client requests for them using the ticket_request extension.
Default is 4.
</dd>
<dt id="ech">ech:</dt>
<dd>
This experimental attribute controls the use of <a href="https://datatracker.ietf.org/doc/draft-ietf-tls-esni/">TLS Encrypted Client Hello extension (draft-15)</a>.
The attribute takes a sequence of mappings, each of them defining one ECH configuration.
<?= $ctx->{example}->('Encrypted Clint hello', <<'EOT')
ssl:
  key-file: /path/to/rsa.key
  certificate-file: /path/to/rsa.crt
  ech:
  - key-file: /path/to/ech.key
    config-id: 11
    public-name: public-name.example.net
    cipher-suite: [ HKDF-SHA256/AES-128-GCM ]
EOT
?>
<p>
The example above defines one ECH configuration that uses <code>/path/to/ech.key</code> as the semi-static ECDH key with a config-id of 11, with the public-name being <code>public-name.example.net</code>, and the HPKE SymmetricCipherSuite being <code>HKDF-SHA256/AES-128-GCM</code>.
</p>
<p>
In addition to these four attributes, following attributes may be specified.
</p>
<p>
<code>max-name-length</code> specifies the maximum-name-length field of an ECH confguration (default: 64).
</p>
<p>
<code>advertise</code> takes either <code>YES</code> (default) or <code>NO</code> as the argument.
This argument indicates if given ECH configuration should be advertised as part of <code>retry_configs</code> (draft-ietf-tls-esni-15; section 5).
</p>
<p>
When removing a stale ECH configuration, its <code>advertise</code> attribute should be set at first to <code>NO</code> so that the stale configuration would not be advertised.
Then, after waiting for the expiry of caches containing the stale configuration, the stale ECH configuration can be removed.
This may take long depending on the TTL of the HTTPS / SVC DNS resource record advertising the configuration.
</p>
The <code>ech</code> attribute must be set only in the first <code>ssl</code> attribute that binds to a particular address.
</dd>
<dt id="neverbleed">neverbleed:</dt>
<dd>
unless set to <code>OFF</code>, H2O isolates SSL private key operations to a different process by using <a href="https://github.com/h2o/neverbleed">Neverbleed</a>.
Default is <code>ON</code>.
</dl>
<p>
<a href="configure/base_directives.html#ssl-session-resumption"><code>ssl-session-resumption</code></a> directive is provided for tuning parameters related to session resumption and session tickets.
</p>
<h4 id="listen-cc">The CC Attribute</h4>
<p>
The <code>CC</code> attribute specifies the congestion controller to be used for incoming HTTP connections.
</p>
<p>
For TCP connections, the congestion controller is set using the <code>TCP_CONGESTION</code> socket option on platforms that have support for that socket option.
To find out the default and the list of supported congestion controllers, please refer to <code>man 7 tcp</code>.
If the platform does not have support for that socket option, the attribute has no effect.
</p>
<p>
For QUIC connections, the congestion controller is one of <code>Reno</code>, <code>Cubic</code>, <code>Pico</code>.
The default is <code>Reno</code>.
</p>
<h4 id="listen-initcwnd">The Initcwnd Attribute</h4>
<p>
The <code>initcwnd</code> attribute specifies the initial congestion window of each incoming HTTP connection in the unit of packets.
At the moment, this option only applies to QUIC. It has no effect for TCP connections.
</p>
<h4 id="listen-proxy-protocol">The Proxy-Protocol Attribute</h4>
<p>
The <code>proxy-protocol</code> attribute (i.e. the value of the attribute must be either <code>ON</code> or <code>OFF</code>) specifies if the server should recognize the information passed via <a href="http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt">"the PROXY protocol</a> in the incoming connections.
The protocol is used by L4 gateways such as <a href="http://aws.amazon.com/jp/elasticloadbalancing/">AWS Elastic Load Balancing</a> to send peer address to the servers behind the gateways.
</p>
<p>
When set to <code>ON</code>, H2O standalone server tries to parse the first octets of the incoming connections as defined in version 1 of the specification, and if successful, passes the addresses obtained from the protocol to the web applications and the logging handlers.
If the first octets do not accord with the specification, it is considered as the start of the SSL handshake or as the beginning of an HTTP request depending on whether if the <code>ssl</code> attribute has been used.
</p>
<p>
Default is <code>OFF</code>.
</p>
<h4 id="listen-sndbuf">The Sndbuf and Rcvbuf Attributes</h4>
<p>
The <code>sndbuf</code> and <code>rcvbuf</code> attributes specify the send and receive buffer size for each TCP or UNIX socket used for accepting incoming HTTP connections.
If set, the values of these attributes are applied to the sockets using <code>SO_SNDBUF</code> and <code>SO_RCVBUF</code> socket options.
</p>
<p>
These attributes have no effect for QUIC connections.
</p>
<h4 id="listen-unix-socket">Listening to a Unix Socket</h4>
<p>
If the <code>type</code> attribute is set to <code>unix</code>, then the <code>port</code> attribute is assumed to specify the path of the unix socket to which the standalone server should bound.
Also following attributes are recognized.
</p>
<dl>
<dt>owner</dt>
<dd>
username of the owner of the socket file.
If omitted, the socket file will be owned by the launching user.
</dd>
<dt>group</dt>
<dd>
name of the group of the socket file.
If omitted, group ID associated to the socket file will be the group ID of the owner.
</dd>
<dt>permission</dt>
<dd>
an octal number specifying the permission of the socket file.
Many operating systems require write permission for connecting to the socket file.
If omitted, the permission of the socket file will reflect the umask of the calling process.
</dd>
</dl>
<?= $ctx->{example}->('Listening to a Unix Socket accessible only by www-data', <<'EOT')
listen:
  type:       unix
  port:       /tmp/h2o.sock
  owner:      www-data
  permission: 600
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "capabilities",
    levels => [ qw(global) ],
    desc   => "Set capabilities to be added to the process before dropping root privileges.",
)->(sub {
?>
<p>
This directive can be used only on Linux.
The argument is a YAML sequence of capabilites, where each capability is a name that is accepted by <code>cap_from_name</code>.
See <code>man 7 capabilities</code> for details.
</p>
? })

<?
$ctx->{directive}->(
    name   => "error-log",
    levels => [ qw(global) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#error-log.emit-request-errors"><code>error-log.emit-request-errors</code></a>
EOT
    desc   => q{Path of the file to which error logs should be appended.},
)->(sub {
?>
<p>
Default is stderr.
</p>
<p>
If the path starts with <code>|</code>, the rest of the path is considered as a command to which the logs should be piped.
</p>
<?= $ctx->{example}->('Log errors to file', <<'EOT')
error-log: /path/to/error-log-file
EOT
?>
<?= $ctx->{example}->('Log errors through pipe', <<'EOT')
error-log: "| rotatelogs /path/to/error-log-file.%Y%m%d 86400"
EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "error-log.emit-request-errors",
    levels  => [ qw(global host path extension) ],
    since   => "2.1",
    see_also => render_mt(<<'EOT'),
<a href="configure/access_log_directives.html#access-log"><code>access-log</code></a>
<a href="configure/base_directives.html#error-log"><code>error-log</code></a>
EOT
    default => "error-log.emit-request-errors: ON",
    desc    => q{Sets whether if request-level errors should be emitted to the error log.},
)->(sub {
?>
By setting the value to <code>OFF</code> and by using the <code>%{error}x</code> specifier of the <a href="configure/access_log_directives.html">access-log</a> directive, it is possible to log request-level errors only to the access log.
? })

<?
$ctx->{directive}->(
    name    => "h2olog",
    levels  => [ qw(host) ],
    default => "h2olog: OFF",
    desc    => q{Under the path <code>/.well-known/h2olog</code> for the current host, registers a h2olog handler that emits the internals of traffic that the h2o process is handling.},
)->(sub {
?>
<p>
The <code>h2olog</code> command can be used to gather information through this endpoint.
As the handler emits the internals of h2o to the client, only requests via a UNIX socket are accepted.
</p>
<p>
This directive takes one of the following three arguments:
<dl>
<dt>off</dt>
<dd>The h2olog endpoint is disabled.</dt>
<dt>on</dt>
<dd>The h2olog endpoint is enabled, but only information to gather performance data will be emitted.</dd>
<dt>appdata</dt>
<dd>The h2olog endpoint is enabled, and in addition to information necessary for gathering performance data, some payload of HTTP is emitted as well. The additional information might help diagnose issues specific to certain HTTP connections but might include sensitive information (e.g., HTTP cookies).</dd>
</dl>
</p>
? })

<?
$ctx->{directive}->(
    name    => "handshake-timeout",
    levels  => [ qw(global) ],
    default => "handshake-timeout: 10",
    desc    => q{Maximum time (in seconds) that can be spent by a connection before it becomes ready to accept an HTTP request.},
)->(sub {
?>
Times spent for receiving <a href="configure/base_directives.html#listen-proxy-protocol">the PROXY protocol</a> and TLS handshake are counted.
? })

<?
$ctx->{directive}->(
    name         => "io_uring-batch-size",
    levels       => [ qw(global) ],
    default      => "io_uring-batch-size: 1",
    desc         => q{Number of io_uring calls to issue at once. Increasing this number might reduce overhead.},
    experimental => 1,
    see_also     => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.io_uring"><code>file.io_uring</code></a>
EOT
)->(sub {})
?>

<?
$ctx->{directive}->(
    name   => "limit-request-body",
    levels => [ qw(global) ],
    desc   => q{Maximum size of request body in bytes (e.g. content of POST).},
)->(sub {
?>
<p>
Default is 1073741824 (1GB).
</p>
? })

<?
$ctx->{directive}->(
    name     => "max-connections",
    levels   => [ qw(global) ],
    default  => 'max-connections: 1024',
    desc     => q{Maximum number of incoming connections to handle at once.},
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#max-quic-connections"><code>max-quic-connections</code></a>
<a href="configure/base_directives.html#soft-connection-limit"><code>soft-connection-limit</code></a>
EOT
)->(sub {
?>
This includes TCP and QUIC connections.
? })

<?
$ctx->{directive}->(
    name         => "max-quic-connections",
    levels       => [ qw(global) ],
    desc         => q{Maximum number of incoming QUIC connections to handle at once.},
    experimental => 1,
    see_also     => render_mt(<<'EOT'),
<a href="configure/base_directives.html#num-quic-threads"><code>num-quic-threads</code></a>
EOT
)->(sub {
?>
<p>
By default, maximum number of incoming connections is governed by <code>max-connections</code> regardless of the transport protocol (i.e., TCP or QUIC) being used.
</p>
<p>
This directive introduces an additional cap for incoming QUIC connections. By setting <code>max-quic-connections</code> to a value smaller than <code>max-connections</code>, it would be possible to serve incoming requests that arrive on top of TCP (i.e., HTTP/1 and HTTP/2) even when there are issues with handling QUIC connections.
</p>
? })

<?
$ctx->{directive}->(
    name    => "max-delegations",
    levels  => [ qw(global) ],
    default => 'max-delegations: 5',
    desc    => q{Limits the number of delegations (i.e. fetching the response body from an alternate source as specified by the <code>X-Reproxy-URL</code> header).},
)->(sub {});

$ctx->{directive}->(
    name    => "max-reprocesses",
    levels  => [ qw(global) ],
    default => 'max-reprocesses: 5',
    desc    => q{Limits the number of internal redirects.},
)->(sub {});

<?
$ctx->{directive}->(
    name     => "max-spare-pipes",
    levels   => [ qw(global) ],
    desc     => q{This setting specifies the maximum number of pipes retained for reuse, when <code>file.io_uring</code> or <code>proxy.zerocopy</code> is used.},
    default  => 0,
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.io_uring"><code>file.io_uring</code></a>, <a href="configure/proxy_directives.html#proxy.zerocopy"><code>proxy.zerocopy</code></a>
EOT
)->(sub {
?>
<p>
The setting can be used to reduce lock contention in the kernel under high load.
</p>
<p>
This maximum is applied per each worker thread.
</p>
<p>
Setting this value to 0 will cause no pipes to be retained by h2o; the pipes will be closed after they are used.
In this case, h2o will create new pipes each time they are needed.
</p>
<p>
In previous versions, this configuration directive was called <code>proxy.max-spare-pipes</code>.
</p>
? })

<?
$ctx->{directive}->(
    name         => "neverbleed-offload",
    levels       => [ qw(global) ],
    default      => "neverbleed-offload: OFF",
    experimental => 1,
    desc         => "Sets an offload engine to be used with neverbleed.",
)->(sub {
?>
<p>
When <a href="configure/base_directives.html#neverbleed">neverbleed</a> is in use, RSA private key operations can be offload to accelerators using the <a href="https://www.intel.com/content/www/us/en/architecture-and-technology/intel-quick-assist-technology-overview.html" target=_blank>Intel QuickAssist technology</a>.
</p>
<p>This directive takes one of the three values that changes how the accelerators are used:
<ul>
<li>OFF - the accelerator is not used</li>
<li>QAT - use of QAT is enforced; startup will fail if the acclerator is unavailable</li>
<li>QAT-AUTO - QAT is used if available</li>
</ul>
</p>
<?
});

$ctx->{directive}->(
    name    => "num-name-resolution-threads",
    levels  => [ qw(global) ],
    default => 'num-name-resolution-threads: 32',
    desc    => q{Maximum number of threads to run for name resolution.},
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "num-ocsp-updaters",
    levels  => [ qw(global) ],
    since   => "2.0",
    default => 'num-ocsp-updaters: 10',
    desc    => q{Maximum number of OCSP updaters.},
)->(sub {
?>
<p>
<a href="https://en.wikipedia.org/wiki/OCSP_stapling">OSCP Stapling</a> is an optimization that speeds up the time spent for establishing a TLS connection.
In order to <i>staple</i> OCSP information, a HTTP server is required to periodically contact the certificate authority.
This directive caps the number of the processes spawn for collecting the information.
</p>
<p>
The use and the update interval of OCSP can be configured using the <a href="configure/base_directives.html#listen-ssl">SSL attributes</a> of the <a href="configure/base_directives.html#listen"><code>listen</code></a> configuration directive.
</p>
? });

<?
$ctx->{directive}->(
    name   => "num-threads",
    levels => [ qw(global) ],
    desc   => q{Number of worker threads.},
)->(sub {
?>
<p>
By default, the number of worker threads spawned by h2o is the number of the CPU cores connected to the system as obtained by <code>getconf NPROCESSORS_ONLN</code>.
</p>
<p>
This directive is used to override the behavior.
</p>
<p>
If the argument is a YAML scalar, it specifies in integer the number of worker threads to spawn.
</p>
<p>
If the argument is a YAML sequence, it specifies a list of CPU IDs on each of which one worker thread will be spawned and pinned.
This mode can be used oly on systems that have <code>pthread_setaffinity_np</code>.
</p>
? })

<?
$ctx->{directive}->(
    name         => "num-quic-threads",
    levels       => [ qw(global) ],
    desc         => q{Restricts the number of worker threads that handle incoming QUIC connections.},
    experimental => 1,
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#max-quic-connections"><code>max-quic-connections</code></a>
EOT
)->(sub {
?>
<p>
By default, all worker threads handle incoming QUIC connections as well as TCP connections.
</p>
<p>
If <a href="configure/base_directives.html#num-threads"><code>num-threads</code></a> was given a YAML sequence specifying the CPU IDs on which each worker thread will run, the threads pinned to first <code>num-quic-threads</code> threads will handle incoming QUIC connections.
</p>
? })

<?
$ctx->{directive}->(
    name   => "pid-file",
    levels => [ qw(global) ],
    desc   => q{Name of the file to which the process id of the server should be written.},
)->(sub {
?>
<p>
Default is none.
</p>
? })

<?
$ctx->{directive}->(
    name   => "tcp-fastopen",
    levels => [ qw(global) ],
    desc   => q{Size of the queue used for TCP Fast Open.},
)->(sub {
?>
<p>
<a href="https://en.wikipedia.org/wiki/TCP_Fast_Open">TCP Fast Open</a> is an extension to the TCP/IP protocol that reduces the time spent for establishing a connection.
On Linux that support the feature, the default value is <code>4,096</code>.
On other platforms the default value is <code>0</code> (disabled).
</p>
? })

<?
$ctx->{directive}->(
    name     => "send-server-name",
    levels   => [ qw(global) ],
    since    => '2.0',
    desc     => q{Sets whether if the <code>server</code> response header should be sent or forwarded from backend.},
    default  => q{send-server-name: ON},
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#server-name"><code>server-name</code></a>
EOT
)->(sub {
?>
<p>
By setting the value to (<code>ON</code> or <code>OFF</code>) indicating whether if the <code>server</code> response header should be sent. And by setting the value to <code>preserve</code>, it forwards the value received from the backend when proxying.
</p>
? })

<?
$ctx->{directive}->(
    name => "server-name",
    levels   => [ qw(global) ],
    since    => '2.0',
    desc     => q{Lets the user override the value of the <code>server</code> response header.},
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#send-server-name"><code>send-server-name</code></a>
EOT
)->(sub {
?>
The default value is <code>h2o/VERSION-NUMBER</code>.
? })

<?
$ctx->{directive}->(
    name     => "setenv",
    levels   => [ qw(global host path extension) ],
    since    => '2.0',
    desc     => 'Sets one or more environment variables.',
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#unsetenv"><code>unsetenv</code></a>
EOT
)->(sub {
?>
<p>
Environment variables are a set of key-value pairs containing arbitrary strings, that can be read from applications invoked by the standalone server (e.g. <a href="configure/fastcgi_directives.html">fastcgi handler</a>, <a href="configure/mruby_directives.html">mruby handler</a>) and the access logger.
</p>
<p>
The directive is applied from outer-level to inner-level.
At each level, the directive is applied after the <a href="configure/base_directives.html#unsetenv"><code>unsetenv</code></a> directive at the corresponding level is applied.
</p>
<p>
Environment variables are retained through internal redirections.
</p>
<?= $ctx->{example}->('Setting an environment variable named <code>FOO</code>', <<'EOT')
setenv:
  FOO: "value_of_FOO"
EOT
?>
? })

<?
$ctx->{directive}->(
    name     => "unsetenv",
    levels   => [ qw(global host path extension) ],
    since    => '2.0',
    desc     => 'Unsets one or more environment variables.',
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#setenv"><code>setenv</code></a>
EOT
)->(sub {
?>
<p>
The directive can be used to have an exception for the paths that have an environment variable set, or can be used to reset variables after an internal redirection.
</p>
<?= $ctx->{example}->('Setting environment variable for <code>example.com</code> excluding <code>/specific-path</code>', <<'EOT')
hosts:
  example.com:
    setenv:
      FOO: "value_of_FOO"
    paths:
      /specific-path:
        unsetenv:
          - FOO
      ...
EOT
?>
? })

<?
$ctx->{directive}->(
    name     => "send-informational",
    levels   => [ qw(global) ],
    default => 'except-h1',
    since    => '2.3',
    desc     => 'Specifies the client protocols to which H2O can send 1xx informational responses.',
)->(sub {
?>
<p>
This directive can be used to forward 1xx informational responses (e.g., <a href="https://www.rfc-editor.org/rfc/rfc8297.html" target=_blank>103 Early Hints</a>) generated by <a href="configure/proxy_directives.html">upstream servers</a> or <a href="configure/headers_directives.html">headers</a> directive to the clients.
</p>
<p>
If the value is <code>all</code>, H2O always sends informational responses to the client whenever possible (i.e. unless the procotol is HTTP/1.0).
</p>
<p>
If the value is <code>none</code>, H2O never sends informational responses to the client.
</p>
<p>
If the value is <code>except-h1</code>, H2O sends informational if the protocol is not HTTP/1.x.
</p>
? })

<?
$ctx->{directive}->(
    name     => "soft-connection-limit",
    levels   => [ qw(global) ],
    desc     => "Number of connections above which idle connections are closed agressively.",
)->(sub {
?>
<p>
H2O accepts up to <a href="configure/base_directives.html#max-connections"><code>max-connections</code></a> TCP connections and <a href="configure/base_directives.html#max-quic-connections"><code>max-quic-connections</code></a> QUIC connections.
Once the number of connections reach these maximums, new connection attempts are ignored until existing connections close.
</p>
<p>
To reduce the possibility of the number of connections reaching the maximum and new connection attempts getting ignored, <code>soft-connection-limit</code> can be used to introduce another threshold.
When <code>soft-connection-limit</code> is set, connections that have been idle at least for <a href="configure/base_directives.html#soft-connection-limit.min-age"><code>soft-connection-limit.min-age</code></a> seconds will start to get closed until the number of connections becomes no greater than <code>soft-connection-limit</code>.
</p>
<p>
As the intention of this directive is to close connections more agressively under high load than usual, <code>soft-connection-limit.min-age</code> should be set to a smaller value than the other idle timeouts; e.g., <a href="configure/http1_directives.html#http1-request-timeout"><code>http1-request-timeout</code></a>, <a href="configure/http2_directives.html#http2-idle-timeout"><code>http2-idle-timeout</code></a>.
</p>
<?
});

$ctx->{directive}->(
    name   => "soft-connection-limit.min-age",
    levels => [ qw(global) ],
    desc   => "Minimum amount of idle time to be guaranteed for HTTP connections even when the connections are closed agressively due to the number of connections exceeding <code>soft-connection-limit</code>.",
    default => "soft-connection-limit.min-age: 30",
)->(sub {
?>
<p>
See <a href="configure/base_directives.html#soft-connection-limit"><code>soft-connection-limit</code></a>.
</p>
? });

<?
$ctx->{directive}->(
    name   => "ssl-offload",
    levels => [ qw(global) ],
    desc   => "Knob for changing how TLS encryption is handled.",
    default => "ssl-offload: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/proxy_directives.html#proxy.zerocopy"><code>proxy.zerocopy</code></a>
EOT
)->(sub {
?>
<p>
This directive takes one of the following values:
<ul>
<li><code>OFF</code> - TLS encryption is handled in userspace and the encrypted bytes are sent to the kernel using a write (2) system call.</li>
<li><code>kernel</code> - TLS encryption is offloaded to the kernel. When the network interface card supports TLS offloading, actual encryption might get offloaded to the interface, depending on the kernel configuration.</li>
<li><code>zerocopy</code> - TLS encryption is handled in userspace, but if the encryption logic is capable of writing directly to main memory without polluting the cache, the encrypted data is passed to the kernel without copying (i.e., sendmsg (2) with  <code>MSG_ZEROCOPY</code> socket option is used). Otherwise, this option is identical to <code>OFF</code>. This option minimizes cache pollution next to hardware offload.</li>
</ul>
</p>
<p>
<code>Kernel</code> option can be used only on Linux.
<code>Zerocopy</code> is only available on Linux running on CPUs that support the necessary features; see <a href="https://github.com/h2o/picotls/pull/384" target=_blank>picotls PR#384</a> and <a href="https://github.com/h2o/h2o/pull/3007" target=_blank>H2O PR#3007</a>.
</p>
? })

<?
$ctx->{directive}->(
    name   => "ssl-session-resumption",
    levels => [ qw(global) ],
    desc   => q{Configures cache-based and ticket-based session resumption.},
)->(sub {
?>
<p>
To reduce the latency introduced by the TLS (SSL) handshake, two methods to resume a previous encrypted session are defined by the Internet Engineering Task Force.
H2O supports both of the methods: cache-based session resumption (defined in <a href="https://tools.ietf.org/html/rfc5246">RFC 5246</a>) and ticket-based session resumption (defined in <a href="https://tools.ietf.org/html/rfc5077">RFC 5077</a>).
</p>
<?= $ctx->{example}->('Various session-resumption configurations', <<'EOT');
# use both methods (storing data on internal memory)
ssl-session-resumption:
    mode: all

# use both methods (storing data on memcached running at 192.168.0.4:11211)
ssl-session-resumption:
    mode: all
    cache-store: memcached
    ticket-store: memcached
    cache-memcached-num-threads: 8
    memcached:
        host: 192.168.0.4
        port: 11211

# use ticket-based resumption only (with secrets used for encrypting the tickets stored in a file)
ssl-session-resumption:
    mode: ticket
    ticket-store: file
    ticket-file: /path/to/ticket-encryption-key.yaml
EOT
?>
<h4 id="ssl-session-resumption-methods">Defining the Methods Used</h4>
<p>
The <code>mode</code> attribute defines which methods should be used for resuming the TLS sessions.
The value can be either of: <code>off</code>, <code>cache</code>, <code>ticket</code>, <code>all</code>.
Default is <code>all</code>.
</p>
<p>
If set to <code>off</code>, session resumption will be disabled, and all TLS connections will be established via full handshakes.
If set to <code>all</code>, both session-based and ticket-based resumptions will be used, with the preference given to the ticket-based resumption for clients supporting both the methods.
</p>
<p>
For each method, additional attributes can be used to customize their behaviors.
Attributes that modify the behavior of the disabled method are ignored.
</p>
<h4 id="ssl-session-resumption-cache-based">Attributes for Cache-based Resumption</h4>
<p>
Following attributes are recognized if the cache-based session resumption is enabled.
Note that <code>memcached</code> attribute must be defined as well in case the <code>memcached</code> cache-store is used.
</p>
<dl>
<dt>cache-store:</dt>
<dd>
<p>
defines where the cache should be stored, must be one of: <code>internal</code>, <code>memcached</code>.
Default is <code>internal</code>.
</p>
<p>
Please note that if you compiled h2o with OpenSSL 1.1.0 ~ 1.1.0f, session resumption with external cache store would fail due to bug of OpenSSL.
</p>
</dd>
<dt>cache-memcached-num-threads:</dt>
<dd>defines the maximum number of threads used for communicating with the memcached server.
Default is <code>1</code>.
</dd>
<dt>cache-memcached-prefix:</dt>
<dd>
for the <code>memcached</code> store specifies the key prefix used to store the secrets on memcached.
Default is <code>h2o:ssl-session-cache:</code>.
</dd>
</dl>

<h4 id="ssl-session-resumption-ticket-based">Attributes for Ticket-based Resumption</h4>
<p>
Ticket-based session resumption uses ticket encryption key(s) to encrypt the keys used for encrypting the data transmitted over TLS connections.
To achieve <a href="https://en.wikipedia.org/wiki/Forward_secrecy" target="_blank">forward-secrecy</a> (i.e. protect past communications from being decrypted in case the ticket encryption key gets obtained by a third party), it is essential to periodically roll over the encyrption key.
</p>
<p>
Among the three types of stores supported for ticket-based session resumption, the <code>internal</code> store and <code>memcached</code> store implement automatic roll-over of the secrets.
A new ticket encryption key is created every 1/4 of the session lifetime (defined by the <code>lifetime</code> attribute), and they expire (and gets removed) after 5/4 of the session lifetime elapse.
</p>
<p>
For the <code>file</code> store, it is the responsibility of the web-site administrator to periodically update the secrets.  H2O monitors the file and reloads the secrets when the file is altered.
</p>
<p>
Following attributes are recognized if the ticket-based resumption is enabled.
</p>
<dl>
<dt>ticket-store:</dt>
<dd>defines where the secrets for ticket-based resumption should be / is stored, must be one of: <code>internal</code>, <code>file</code>, <code>memcached</code>.
Default is <code>internal</code>.
<dt>ticket-cipher:</dt>
<dd>
for stores that implement automatic roll-over, specifies the cipher used for encrypting the tickets.
The value must be one recognizable by <code>EVP_get_cipherbyname</code>.
Default is <code>aes-256-cbc</code>.
<dt>ticket-hash:</dt>
<dd>
for stores that implement automatic roll-over, specifies the cipher used for digitally-signing the tickets.
The value must be one recognizable by <code>EVP_get_digestbyname</code>.
Default is <code>sha-256</code>.
</dd>
<dt>ticket-file:</dt>
<dd>for the <code>file</code> store specifies the file in which the secrets are stored</dd>
<dt>ticket-memcached-key:</dt>
<dd>
for the <code>memcached</code> store specifies the key used to store the secrets on memcached.
Default is <code>h2o:ssl-session-ticket</code>.
</dd>
</dl>

<h4 id="ssl-session-resumption-ticket-format">Format of the Ticket Encryption Key</h4>
<p>
Either as a file (specified by <code>ticket-file</code> attribute) or as a memcached entry (<code>ticket-memcached-key</code>), the encryption keys for the session tickets are stored as a sequence of YAML mappings.
Each mapping must have all of the following attributes set.
</p>
<dl>
<dt>name</dt>
<dd>a string of 32 hexadecimal characters representing the name of the ticket encryption key.
The value is only used for identifying the key; it can be generated by calling a PRNG.</dd>
<dt>cipher</dt>
<dd>name of the symmetric cipher used to protect the session tickets.
The only supported values are: <code>aes-128-cbc</code> and <code>aes-256-cbc</code> (the default).</dd>
<dt>hash</dt>
<dd>the hash algorithm to be used for validating the session tickets.
The only supported value is: <code>sha256</code>.</dd>
<dt>key</dt>
<dd>concatenation of the key for the symmetric cipher and the HMAC, encoded as hexadecimal characters.
The length of the string should be the sum of the cipher key length plus the hash key length, mulitplied by two (due to hexadicimal encoding); i.e. 96 bytes for <code>aes-128-cbc/sha256</code> or 128 bytes for <code>aes-256-cbc/sha256</code>.</dd>
<dt>not_before</dt>
<dd>the time from when the key can be used for encrypting the session tickets.
The value is encoded as milliseconds since epoch (Jan 1 1970).
When rotating the encryption keys manually on multiple servers, you should set the <code>not_before</code> attribute of the newly added key to some time in the future, so that the all the servers will start using the new key at the same moment.</dd>
<dt>not_after</dt>
<dd>until when the key can be used for encrypting the session tickets</dd>
</dl>
<p>
The following example shows a YAML file containing two session ticket encryption keys.
The first entry is used for encrypting new keys on Jan 5 2018.
The second entry is used for encrypting new keys on Jan 6 2018.
</p>
<?= $ctx->{example}->('session ticket key file', << 'EOT');
- name:       c173437296d6c2307fd39b40c944c227
  cipher:     aes-256-cbc
  hash:       sha256
  key:        e54210a0f6a6319aa155a33b8babd772319bad9f27903746dfbe6df7a4058485a8cedb057cfc5b70080cda2354fc3e13
  not_before: 1515110400000 # 2018-01-05 00:00:00.000
  not_after:  1515196799999 # 2018-01-05 23:59:59.999
- name:       bb1a15d75dc498624890dc5a7e164675
  cipher:     aes-256-cbc
  hash:       sha256
  key:        b4120bc903d6521fefa357ac322561fc97aa9e5ae5e18eade64832439b9095ab80f8429d6b50ff9c4c5eca1f90717d30
  not_before: 1515196800000 # 2018-01-06 00:00:00.000
  not_after:  1515283199999 # 2018-01-06 23:59:59.999
EOT
?>

<h4 id="ssl-session-resumption-other">Other Attributes</h4>
<p>
Following attributes are common to cache-based and ticket-based session resumption.
</p>
<dl>
<dt>lifetime:</dt>
<dd>
defines the lifetime of a TLS session; when it expires the session cache entry is purged, and establishing a new connection will require a full TLS handshake.
Default value is <code>3600</code> (in seconds).
</dd>
<dt>memcached:</dt>
<dd>
specifies the location of memcached used by the <code>memcached</code> stores.
The value must be a mapping with <code>host</code> attribute specifying the address of the memcached server, and optionally a <code>port</code> attribute specifying the port number (default is <code>11211</code>).
By default, the memcached client uses the <a href="https://github.com/memcached/memcached/blob/master/doc/protocol-binary.xml">BINARY protocol</a>.
Users can opt-in to using the legacy <a href="https://github.com/memcached/memcached/blob/master/doc/protocol.txt">ASCII protocol</a> by adding a <code>protocol</code> attribute set to <code>ASCII</code>.
</dd>
? })

<?
$ctx->{directive}->(
    name     => "strict-match",
    levels   => [ qw(host) ],
    desc     => q{A boolean flag designating if the current host element should not be considered as the fallback element.},
    default  => q{strict-match: OFF},
)->(sub {
?>
See <a href="configure/base_directives.html#hosts"><code>hosts</code></a>.
? })

<?
$ctx->{directive}->(
    name    => "tcp-reuseport",
    levels  => [ qw(global) ],
    desc    => "A boolean flag designating if TCP socket listeners should be opened with the SO_REUSEPORT option.",
    default => "tcp-reuseport: OFF",
)->(sub {});
?>

<?
$ctx->{directive}->(
    name     => "temp-buffer-path",
    levels   => [ qw(global) ],
    desc     => q{Directory in which temporary buffer files are created.},
    default  => q{temp-buffer-path: "/tmp"},
    since    => "2.0",
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#user"><code>user</code></a>
<a href="configure/base_directives.html#temp-buffer-threshold"><code>temp-buffer-threshold</code></a>
EOT
)->(sub {
?>
<p>
H2O uses an internal structure called <code>h2o_buffer_t</code> for buffering various kinds of data (e.g. POST content, response from upstream HTTP or FastCGI server).
When amount of the data allocated in the buffer exceeds the default value of 32MB, it starts allocating storage from the directory pointed to by the directive.
The threshold can be tuned or disabled using the <code>temp-buffer-threshold</code> directive.
</p>
<p>
By using the directive, users can set the directory to one within a memory-backed file system (e.g. <a href="https://en.wikipedia.org/wiki/Tmpfs">tmpfs</a>) for speed, or specify a disk-based file system to avoid memory pressure.
</p>
<p>
Note that the directory must be writable by the running user of the server.
</p>
? })

<?
$ctx->{directive}->(
    name     => "temp-buffer-threshold",
    levels   => [ qw(global) ],
    desc     => q{Minimum size to offload a large memory allocation to a temporary buffer.},
    default  => q{temp-buffer-threshold: "33554432"},
    since    => "2.2.5",
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#temp-buffer-path"><code>temp-buffer-path</code></a>
EOT
)->(sub {
?>
<p>
Users can use this directive to tune the threshold for when the server should use temporary buffers.
The minimum value accepted is 1MB (1048576) to avoid overusing these buffers, which will lead to performance degradation.
If omitted, the default of 32MB is used.
</p>
<p>
The user can disable temporary buffers altogether by setting this threshold to <code>OFF</code>.
</p>
? })

<?
$ctx->{directive}->(
    name   => "user",
    levels => [ qw(global) ],
    desc   => q{Username under which the server should handle incoming requests.},
)->(sub {
?>
<p>
If the directive is omitted and if the server is started under root privileges, the server will attempt to <code>setuid</code> to <code>nobody</code>.
</p>
? })

<?
$ctx->{directive}->(
    name   => "crash-handler",
    levels => [ qw(global) ],
    desc   => q{Script to invoke if <code>h2o</code> receives a fatal signal.},
    default  => q{crash-handler: "${H2O_ROOT}/share/h2o/annotate-backtrace-symbols"},
    since    => "2.1",
)->(sub {
?>
<p>Note: this feature is only available when linking to the GNU libc.</p>

<p>The script is invoked if one of the <code>SIGABRT</code>,
<code>SIGBUS</code>, <code>SIGFPE</code>, <code>SIGILL</code> or
<code>SIGSEGV</code> signals is received by <code>h2o</code>.</p>

<p><code>h2o</code> writes the backtrace as provided by
<code>backtrace()</code> and <code>backtrace_symbols_fd</code> to the
standard input of the program.</p>

<p>If the path is not absolute, it is prefixed with <code>${H2O_ROOT}/</code>.</p>
? })

<?
$ctx->{directive}->(
    name   => "crash-handler.wait-pipe-close",
    levels => [ qw(global) ],
    desc   => q{Whether <code>h2o</code> should wait for the crash handler pipe to close before exiting.},
    default  => q{crash-handler.wait-pipe-close: OFF},
    since    => "2.1",
)->(sub {
?>
<p>When this setting is <code>ON</code>, <code>h2o</code> will wait
for the pipe to the crash handler to be closed before exiting.
This can be useful if you use a custom handler that inspects the dying
process.</p>
? })

<?
$ctx->{directive}->(
    name   => "stash",
    levels => [ qw(global host path extension) ],
    desc   => q{Directive being used to store reusable YAML variables.},
    since    => "2.3",
)->(sub {
?>
<p>This directive does nothing itself, but can be used to store YAML variables and reuse those using <a href="configure/syntax_and_structure.html#yaml_alias">YAML Alias</a>.</p>

<?= $ctx->{example}->('Reusing stashed variables across multiple hosts', <<'EOT')
stash:
  ssl: &ssl
    port: 443
  paths: &paths
    /:
      file.dir: /path/to/root
hosts:
  "example.com":
    listen:
      <<: &ssl
      ssl:
        certificate-file: /path/to/example.com.crt
        key-file:         /path/to/example.com.key
    paths: *paths
  "example.org":
    listen:
      <<: &ssl
      ssl:
        certificate-file: /path/to/example.org.crt
        key-file:         /path/to/example.org.key
    paths: *paths
EOT
?>

? })

? })

? })
