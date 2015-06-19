? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Access Log Directives")->(sub {

<p>
This document describes the configuration directives of the access_log handler.
</p>

<?
$ctx->{directive}->(
    name    => "access-log",
    levels  => [ qw(global host path extension) ],
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
</p>

<?= $ctx->{example}->('Emit access log to file using Common Log Format', <<'EOT')
access-log:
    path: /path/to/access-log-file
    format: "%h %l %u %t \"%r\" %>s %b"
EOT
?>

<p>
The list of format strings recognized by H2O is as follows.
</p>

<table>
<tr><th>Format String<th>Description
<tr><td><code>%%</code><td>the percent sign
<tr><td><code>%b</code><td>size of the response body in bytes
<tr><td><code>%H</code><td>request protocol as sent by the client (e.g. <code>HTTP/1.1</code>)
<tr><td><code>%h</code><td>remote address (e.g. <code>1.2.3.4</code>)
<tr><td><code>%l</code><td>remote logname (always <code>-</code>)
<tr><td><code>%m</code><td>request method (e.g. <code>GET</code>, <code>POST</code>)
<tr><td><code>%q</code><td>query string (<code>?</code> is prepended if exists, otherwise an empty string)
<tr><td><code>%r</code><td>request line (e.g. <code>GET / HTTP/1.1</code>)
<tr><td><code>%s</code><td>status code (e.g. <code>200</code>)
<tr><td><code>%U</code><td>requested URL path, not including the query string
<tr><td><code>%u</code><td>remote user if the request was authenticated (always <code>-</code>)
<tr><td><code>%V</code><td>requested server name (or the default server name if not specified by the client)
<tr><td><code>%v</code><td>canonical server name
<tr><td><code>%{<i>HEADERNAME</i>}i</code><td>value of the given request header (e.g. <code>%{user-agent}i</code>)
<tr><td><code>%{<i>HEADERNAME</i>}o</code><td>value of the given response header (e.g. <code>%{set-cookie}o</code>)
</table>

<p>
The default format is <code>%h %l %u %t "%r" %s %b "%{Referer}i" "%{User-agent}i"</code>, a.k.a. the <a href="http://httpd.apache.org/docs/2.4/mod/mod_log_config.html.en#examples" target="_blank">NCSA extended/combined log format</a>.
</p>
? })

? })
