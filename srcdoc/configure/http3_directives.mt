? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/3")->(sub {

<p>
<a href="https://tools.ietf.org/html/rfc9114" target=_blank>HTTP/3</a> uses <a href="https://tools.ietf.org/html/rfc9000" target=_blank>QUIC</a> as the transport protocol.
A <a href="configure/base_directives.html#listen"><code>listen</code></a> directive with a <code>type</code> attribute set to <code>quic</code> instructs the standalone server to bind to a UDP port on which QUIC packets will be sent and received.
The binding must have an <a href="configure/base_directives.html#listen-ssl"><code>ssl</code></a> attribute, as QUIC uses TLS/1.3 as the handshake protocol.
</p>
<p>
The example below setups a server that listens to both TCP port 443 and UDP port 443 using the same certificate and private key.
</p>
<p>
First <code>listen</code> directive binds the server to TCP port 443 with specified credentials, marking that directive as an <a href="configure/syntax_and_structure.html#yaml_alias">YAML alias</a> called <code>&listen_ssl</code>.
Then, it reuses (<a href="configure/syntax_and_structure.html#yaml_merge">YAML merge</a>) the first listen directive, adding <code>type: quic</code> to create a UDP port 443 binding for accepting QUIC connections.
</p>
<?= $ctx->{example}->('Serving HTTP/1,2 and 3 on port 443', <<'EOT')
listen: &listen_ssl
  port: 443
  ssl:
    certificate-file: /path/to-ssl-certificate-file
    key-file: /path/to/ssl-key-file
listen:
  <<: *listen_ssl
  type: quic
EOT
?>

<h4 id="quic-attributes">Fine-tuning QUIC Behavior</h4>
<p>
To fine tune the behavior of QUIC, the <code>quic</code> attribute should be used in place of the <code>type</code> attribute specifying <code>quic</code>.
The <code>quic</code> attribute accepts following parameters.
</p>
<dl>
<dt>amp-limit</dt>
<dd>Amount of data that can be sent to the client before the client address is validated; see <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation" target=_blank>section 8.1 of RFC 9000</a>. Default is 3.</dd>
<dt>handshake-timeout-rtt-multiplier</dt>
<dd>Handshake timeout in the unit of round-trip time. Default is 400.</dd>
<dt>max-initial-handshake-packets</dt>
<dd>Maximum number of Initial packets to be sent before the handshake is deemed to have failed. Default is 1,000.</dd>
<dt>max-streams-bidi</dt>
<dd>Maximum number of client-initated bi-directional streams. This parameter controls the HTTP request concurrency of a HTTP/3 connection. Default is 100.</dd>
<dt>max-udp-payload-size</dt>
<dd>See <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit">Section 18.2 of RFC 9000</a>. Default is 1,472.</dd>
<dt>qpack-encoder-table-capacity</dt>
<dd>Size of the QPACK encoder table. Default is 4,096.</dd>
<dt>retry</dt>
<dd>A boolean flag (<code>OFF</code> or <code>ON</code>) indicating if a Retry packet should be used for validating the client address. Use of Retry packets mitigate denial-of-service attacks at the cost of incurring one additional round-trip for processing the handshake.</dd>
<dt>sndbuf, rcvbuf</dt>
<dd>Size of send and receive buffers, in the unit of bytes. Unlike the TCP counterparts that are per-connection, these buffers are associated to the listening port and applies to all the connections bound to that port.</dd>
</dl>
<p>
The example below reuses a previous binding but sets the <code>retry</code> parameter to <code>ON</code>.
</p>
<?= $ctx->{example}->('HTTP/3 endpoint using Retry packets', <<'EOT')
listen:
  <<: *listen_ssl
  quic:
    retry: ON
EOT
?>
<p>
Also, properties such as <a href="configure/base_directives.html#listen-cc">congestion controller</a> and <a href="configure/base_directives.html#listen-initcwnd">initial congestion window</a> can be tuned using the top-level attribute of <code>listen</code>.
</p>

<h4 id="http3-directives">HTTP/3 Directives</h4>
<p>
Aside from QUIC-level properties, configuration directives listed below are provided for tuning HTTP/3 behavior.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name    => "http3-graceful-shutdown-timeout",
    levels  => [ qw(global) ],
    default => "http3-graceful-shutdown-timeout: 0",
    desc    => "Maximum duration to retain HTTP/3 connections in half-closed state, in seconds.",
)->(sub {
?>
<p>
When a graceful shutdown of h2o is initiated, h2o at first sends a GOAWAY frame indicating the clients that it is initiating shutdown, then after one second, starts rejecting new HTTP requests (a.k.a. half-closed state).
</p>
<p>
This directive controls how long h2o should wait for the peer to close the QUIC connection in this half-closed state, before exitting.
</p>
<p>
If set to zero, this timeout is disabled.
h2o will not shut down until all QUIC connections are closed by the clients or times out.
</p>
? })

<?
$ctx->{directive}->(
    name    => "http3-gso",
    levels  => [ qw(global) ],
    default => "http3-gso: ON",
    desc    => "If Generic Segmentation Offload should be used when sending QUIC packets.",
)->(sub {});
?>

<?
$ctx->{directive}->(
    name    => "http3-idle-timeout",
    levels  => [ qw(global) ],
    default => "http3-idle-timeout: 30",
    desc    => "Idle timeout in the unit of seconds.",
)->(sub {
?>
<p>
Unlike idle timeout of HTTP/1 and HTTP/2, this value should be small because it is faster to re-establish a new connection using 0-RTT than migrating to a different port due to NAT rebinding.
</p>
? });

<?
$ctx->{directive}->(
    name    => "http3-input-window-size",
    levels  => [ qw(global) ],
    default => "http3-input-window-size: 16777216",
    desc    => "Default window size for HTTP request body.",
)->(sub {
?>
<p>
See <a href="configure/http2_directives.html#http2-input-window-size"><code>http2-input-window-size</code></a>.
</p>
? });

<?
$ctx->{directive}->(
    name    => "http3-max-concurrent-streaming-requests-per-connection",
    levels  => [ qw(global) ],
    default => 'http3-max-concurrent-streaming-requests-per-connection: 1',
    desc    => <<'EOT',
Maximum number of streaming requests to be handled concurrently within a single HTTP/3 connection.
EOT
)->(sub {
?>
? });


? })

? })
