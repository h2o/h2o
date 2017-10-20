? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Access Log Directives")->(sub {

<p>
This document describes the configuration directives of the access_log handler.
</p>

<?
$ctx->{directive}->(
    name    => "access-log",
    levels  => [ qw(global host path extension) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/base_directives.html#error-log"><code>error-log</code></a>
<a href="configure/base_directives.html#error-log.emit-request-errors"><code>error-log.emit-request-errors</code></a>
EOT
    desc    => q{The directive sets the path and optionally the format of the access log.},
)->(sub {
?>
<p>
If the supplied argument is a scalar, it is treated as the path of the log file, or if the value starts with a <code>|</code>, it is treated as a command to which the log should be emitted.
</p>
<?= $ctx->{example}->('Emit access log to file', <<'EOT')
access-log: /path/to/access-log-file
EOT
?>
<?= $ctx->{example}->('Emit access log through pipe', <<'EOT')
access-log: "| rotatelogs /path/to/access-log-file.%Y%m%d 86400"
EOT
?>

<p>
If the supplied argument is a mapping, its <code>path</code> property is considered as the path of the log file or the pipe command, and the <code>format</code> property is treated as the format of the log file.
Starting from version 2.2, <code>escape</code> property can be used to specify the escape sequence that should be used to emit unsafe octets.
</p>

<p>
Two forms of escape sequences are supported.
If <code>apache</code> is specified as the value of the <code>escape</code> property, unsafe octets are emitted in the form of <code>\xNN</code>, where N is a hexadecimal number in lower case.
If <code>json</code> is specified, unsafe octets are emitted in the form of <code>\u00NN</code>.
<code>apache</code> is the default escape method.
</p>

<?= $ctx->{example}->('Emit access log to file using Common Log Format', <<'EOT')
access-log:
    path: /path/to/access-log-file
    format: "%h %l %u %t \"%r\" %s %b"
    escape: apache
EOT
?>

<p>
The list of format strings recognized by H2O is as follows.
</p>

<table>
<tr><th>Format String<th>Description
<tr><td><code>%%</code><td>the percent sign
<tr><td><code>%A</code><td>local address (e.g. <code>4.5.6.7</code>)
<tr><td><code>%b</code><td>size of the response body in bytes
<tr><td><code>%H</code><td>request protocol as sent by the client (e.g. <code>HTTP/1.1</code>)
<tr><td><code>%h</code><td>remote address (e.g. <code>1.2.3.4</code>)
<tr><td><code>%l</code><td>remote logname (always <code>-</code>)
<tr><td><code>%m</code><td>request method (e.g. <code>GET</code>, <code>POST</code>)
<tr><td><code>%p</code><td>local port (<code>%{local}p</code> is a synonym that is supported since version 2.2)
<tr><td><code>%{remote}p</code><td>remote port (since version 2.2)
<tr><td><code>%q</code><td>query string (<code>?</code> is prepended if exists, otherwise an empty string)
<tr><td><code>%r</code><td>request line (e.g. <code>GET / HTTP/1.1</code>)
<tr><td><code>%s</code><td>status code sent to client (e.g. <code>200</code>)
<tr><td><code>%&lt;s</code><td>status code received from upstream (or initially generated)
<tr><td><code>%t</code><td>time when the request was received in format: <code>[02/Jan/2006:15:04:05 -0700]</code>
<tr><td><code>%{<i>FORMAT</i>}t</code><td>time when the request was received using the specified format.  <code>FORMAT</code> should be an argument to <code>strftime</code>, or one of:
<table>
<tr><td><code>sec</code><td>number of seconds since Epoch
<tr><td><code>msec</code><td>number of milliseconds since Epoch
<tr><td><code>usec</code><td>number of microseconds since Epoch
<tr><td><code>msec_frac</code><td>millisecond fraction
<tr><td><code>usec_frac</code><td>microsecond fraction
</table>
As an example, it is possible to log timestamps in millisecond resolution using <code>%{%Y/%m/%d:%H:%M:%S}t.%{msec_frac}t</code>, which results in a timestamp like <code>2006-01-02:15:04:05.000</code>.
<tr><td><code>%U</code><td>requested URL path, not including the query string
<tr><td><code>%u</code><td>remote user if the request was authenticated (always <code>-</code>)
<tr><td><code>%V</code><td>requested server name (or the default server name if not specified by the client)
<tr><td><code>%v</code><td>canonical server name
<tr><td><code>%{<i>VARNAME</i>}e</code><td>request environment variable (since version 2.3; see <a href="configure/mruby.html#logging-arbitrary-variable">Logging Arbitrary Variable</a>)
<tr><td><code>%{<i>HEADERNAME</i>}i</code><td>value of the given request header (e.g. <code>%{user-agent}i</code>)
<tr><td><code>%{<i>HEADERNAME</i>}o</code><td>value of the given response header sent to client (e.g. <code>%{set-cookie}o</code>)
<tr><td><code>%&lt;{<i>HEADERNAME</i>}o</code><td>value of the response header received from upstream (or initially generated)
<tr><td><code>%{<i>NAME</i>}x</code><td>various extensions.  <code>NAME</code> must be one listed in the following tables.  A dash (<code>-</code>) is emitted if the directive is not applicable to the request being logged.
<table>
<caption>Access Timings</caption>
<tr><th>Name<th>Description
<tr><td><code>connect-time</code><td>time spent to establish the connection (i.e. since connection gets <code>accept(2)</code>-ed until first octet of the request is received)
<tr><td><code>request-header-time</code><td>time spent receiving request headers
<tr><td><code>request-body-time</code><td>time spent receiving request body
<tr><td><code>request-total-time</code><td>sum of <code>request-header-time</code> and <code>request-body-time</code>
<tr><td><code>process-time</code><td>time spent after receiving request, before starting to send response
<tr><td><code>response-time</code><td>time spent sending response
<tr><td><code>duration</code><td>sum of <code>request-total-time</code>, <code>process-time</code>, <code>response-time</code>
</table>
<table>
<caption>Connection (since v2.0)</caption>
<tr><th>Name<th>Description
<tr><td><code>connection-id</code><td>64-bit internal ID assigned to every client connection
<tr><td><code>ssl.protocol-version</code><td>SSL protocol version obtained from <a href="https://www.openssl.org/docs/manmaster/ssl/SSL_get_version.html"><code>SSL_get_version</code></a>
<tr><td><code>ssl.session-reused</code><td><code>1</code> if the <a href="configure/base_directives.html#ssl-session-resumption">SSL session was reused</a>, or <code>0</code> if not<?= $ctx->{note}->(q{A single SSL connection may transfer more than one HTTP request.}) ?>
<tr><td><code>ssl.session-id</code><td>base64-encoded value of the session id used for resuming the session (since v2.2)
<tr><td><code>ssl.cipher</code><td>name of the <a href="https://tools.ietf.org/html/rfc5246#appendix-A.5">cipher suite</a> being used, obtained from <a href="https://www.openssl.org/docs/manmaster/ssl/SSL_CIPHER_get_name.html">SSL_CIPHER_get_name</a>
<tr><td><code>ssl.cipher-bits</code><td>strength of the cipher suite in bits
</table>
<table>
<caption>HTTP/2 (since v2.0)</caption>
<tr><th>Name<th>Description
<tr><td><code>http2.stream-id</code><td>stream ID
<tr><td><code>http2.priority.received</code><td>colon-concatenated values of <i>exclusive</i>, <i>parent</i>, <i>weight</i>
<tr><td><code>http2.priority.received.exclusive</code><td>exclusive bit of the most recent priority specified by the client
<tr><td><code>http2.priority.received.parent</code><td>parent stream ID of the most recent priority specified by the client
<tr><td><code>http2.priority.received.weight</code><td>weight of the most recent priority specified by the client
</table>
<table>
<caption>Miscellaneous</caption>
<tr><th>Name<th>Description
<tr><td><code>error</code><td>request-level errors. Unless specified otherwise by using the <a href="configure/base_directives.html#error-log.emit-request-errors"><code>error-log.emit-request-errors</code></a> directive, the same messages are emitted to the <a href="configure/base_directives.html#error-log">error-log</a>. (since v2.1)
</table>
</table>

<p>
The default format is <code>%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"</code>, a.k.a. the <a href="http://httpd.apache.org/docs/2.4/mod/mod_log_config.html.en#examples" target="_blank">NCSA extended/combined log format</a>.
</p>
<p>
Note that you may need to quote (and escape) the format string as required by YAML (see <a href="http://www.yaml.org/YAML_for_ruby.html#single-quoted_strings">Yaml Cookbook</a>).
</p>
? })

? })
