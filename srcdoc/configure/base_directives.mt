? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Base Directives")->(sub {

<p>
This document describes the configuration directives common to all the protocols and handlers.
</p>

<?=
$_mt->render_file("directive.mt", {
    name   => "hosts",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Maps <code>host:port</code> to the mappings of per-host configs.
</p>
<p>
The directive specifies the mapping between the authorities (the host or <code>host:port</code> section of an URL) and their configurations.
The directive is mandatory, and must at least contain one entry.
</p>
<p>
When <code>port</code> is omitted, the entry will match the requests targetting the default ports (i.e. port 80 for HTTP, port 443 for HTTPS) with given hostname.
Otherwise, the entry will match the requests targetting the specified port.
</p>
<div class="example">
<div class="caption">Example. A host redirecting all HTTP requests to HTTPS</div>
<pre><code>hosts:
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
</code></pre>
</div>
EOT
}) ?>

<?=
$_mt->render_file("directive.mt", {
    name   => "paths",
    levels => [ qw(host) ],
    desc   => <<'EOT',
<p>
Mapping of paths and their configurations.
</p>
<p>
The mapping is searched using prefix-match.
The entry with the longest path is chosen when more than one matching paths were found.
An <code>404 Not Found</code> error is returned if no matching paths were found.
</p>
<div class="example">
<div class="caption">Example. Configuration with two paths</div>
<pre><code>hosts:
  "www.example.com":
    listen:
      port: 80
    paths:
      "/":
        file.dir: /path/to/doc-root
      "/assets":
        file.dir: /path/to/assets
</code></pre>
</div>
EOT
}) ?>

<?=
$_mt->render_file("directive.mt", {
    name   => "listen",
    levels => [ qw(global host) ],
    desc   => <<'EOT',
<p>
Specifies the port at which the server should listen to.
</p>
<p>
In addition to specifying the port number, it is also possible to designate the bind address or the SSL configuration.
</p>
<div class="example">
<div class="caption">Example. Listen Directives</div>
<pre><code># accept HTTP on port 80 on default address (both IPv4 and IPv6)
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
    certificate-file: /path/to/key-file
</code></pre>
</div>
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
<div class="example">
<div class="caption">Example. Using host-level listeners for HTTPS virtual-hosting</div>
<pre><code>hosts:
  "www.example.com:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_com.key
        certifilate-file: /path/to/www_example_com.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_com
  "www.example.jp:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_jp.key
        certifilate-file: /path/to/www_example_jp.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_jp
</code></pre>
</div>
<p>
The <code style="font-weight: bold;">ssl</code> entry recognizes the following attributes.
</p>
<dl>
<dt>certificate-file:</dt>
<dd>path of the SSL certificate file (mandatory)</dd>
<dt>key-file:</dt>
<dd>path of the SSL private key file (mandatory)</dd>
<dt>minimum-version:</dt>
<dd>
minimum protocol version, should be one of: <code>SSLv2</code>, <code>SSLv3</code>, <code>TLSv1</code>, <code>TLSv1.1</code>, <code>TLSv1.2</code>.
Default is <code>TLSv1</code>
</dd>
<dt>cipher-suite:</dt>
<dd>list of cipher suites to be passed to OpenSSL via SSL_CTX_set_cipher_list (optional)</dd>
<dt>cipher-preference:</dt>
<dd>
side of the list that should be used for selecting the cipher-suite; should be either of: <code>client</code>, <code>server</code>.
Default is <code>client</code>.
</dd>
<dt>ocsp-update-interval:</dt>
<dd>
interval for updating the OCSP stapling data (in seconds), or set to zero to disable OCSP stapling.
Default is <code>14400</code> (4 hours).
</dd>
<dt>ocsp-max-failures</dt>
<dd>
number of consecutive OCSP queriy failures before stopping to send OCSP stapling data to the client.
Default is 3.
</dd>
</dl>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "error-log",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Path of the file to which error logs should be appended.
If the path starts with `|`, the rest of the path is considered as a command to which the logs should be piped.
</p>
<p>
Default is stderr.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "limit-request-body",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Maximum size of request body in bytes (e.g. content of POST).
Default is unlimited.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "max-connections",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Number of connections to handle at once at maximum.
Default is 1,024.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "max-delegations",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Limits the number of delegations (i.e. internal redirects using the <code>X-Reproxy-URL</code> header).
Default is 5.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "num-name-resolution-threads",
    levels => [ qw(global) ],
    desc   => <<'EOT',
Number of threads to run for name resolution.
Default is 32.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "num-threads",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Number of worker threads.
Default is the number of the processors connected to the system as obtained by <code>getconf NPROCESSORS_ONLN</code>.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "pid-file",
    levels => [ qw(global) ],
    desc   => <<'EOT',
Name of the file to which the process id of the server should be written.
Default is none.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name   => "user",
    levels => [ qw(global) ],
    desc   => <<'EOT',
<p>
Username under which the server should handle incoming requests.
</p>
<p>
If the directive is omitted and if the server is started under root privileges, the server will attempt to <code>setuid</code> to <code>nobody</code>.
</p>
EOT
}) ?>

? })
