? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "WebTransport Directives")->(sub {

<p>
<a href="https://datatracker.ietf.org/wg/webtrans/about/">WebTransport</a> lets a client exchange streams and datagrams with a server within a session established by an extended CONNECT request.
H2O supports WebTransport over HTTP/2 (<a href="https://datatracker.ietf.org/doc/draft-ietf-webtrans-http2/">draft-ietf-webtrans-http2-15</a>) and over HTTP/3 (<a href="https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/">draft-ietf-webtrans-http3-16</a>).
Sessions are accepted by handlers; at the moment, the only handler that does so is the echo handler, which is meant for testing.
</p>

<p>
The support is experimental.
Over HTTP/3, at most one session is permitted on each connection, as the flow control of WebTransport is not implemented; also, streams are reset using RESET_STREAM instead of RESET_STREAM_AT; therefore, the peer cannot determine to which session a stream belonged if the stream is reset before its header is received.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name         => "webtransport",
    levels       => [ qw(global) ],
    default      => 'webtransport: OFF',
    experimental => 1,
    desc         => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if WebTransport is advertised to the clients.
EOT
)->(sub {
?>
<p>
When set to <code>ON</code>, H2O advertises the support for WebTransport in the SETTINGS frame.
Over HTTP/2, WebTransport is advertised along with the flow control limits of each session, and only on TLS connections.
Over HTTP/3, it is advertised only when the QUIC DATAGRAM extension is enabled; the streams of the session are subject to the flow control of QUIC.
</p>
? })

<?
$ctx->{directive}->(
    name         => "webtransport.echo",
    levels       => [ qw(path) ],
    default      => 'webtransport.echo: OFF',
    experimental => 1,
    see_also     => render_mt(<<'EOT'),
<a href="configure/webtransport_directives.html#webtransport"><code>webtransport</code></a>
EOT
    desc         => <<'EOT',
Registers a WebTransport echo handler, which is meant for testing.
EOT
)->(sub {
?>
<p>
The handler accepts WebTransport sessions and echoes what it receives:
</p>
<ul>
<li>data received on a bidirectional stream opened by the client is sent back on the same stream</li>
<li>data received on a unidirectional stream opened by the client is sent back on a unidirectional stream opened by the server</li>
<li>datagrams are sent back</li>
<li>resets and STOP_SENDING are mirrored, using the same error code</li>
<li>when the client drains the session, the session is closed</li>
</ul>
<p>
The query string of the request can be used to exercise other code paths:
</p>
<ul>
<li><code>open-bidi=N</code> and <code>open-uni=N</code>: the server opens N (up to 100) streams, each sending <code>stream &lt;id&gt;</code> and a newline before closing</li>
<li><code>drain</code>: the server drains the session immediately</li>
<li><code>close=CODE</code>: the server closes the session with the given error code, once the first bidirectional stream opened by the client has been echoed</li>
</ul>
<p>
Requests that are not WebTransport are passed to the next handler.
</p>
<?= $ctx->{example}->('Echo handler for WebTransport', <<'EOT')
webtransport: ON
hosts:
  default:
    paths:
      /echo:
        webtransport.echo: ON
EOT
?>
? })

? })

? })
