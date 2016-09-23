? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/2 Directives")->(sub {

<p>
H2O provides one of the world's most sophisticated HTTP/2 protocol implementation, including following features.
</p>

<h3 id="prioritization">Prioritization</h3>

<p>
H2O is one of the few servers that fully implement prioritization of HTTP responses conformant to what is defined in the <a href="https://tools.ietf.org/html/rfc7540">HTTP/2 specification</a>.
The server implements a O(1) scheduler that determines which HTTP response should be sent to the client, per every 16KB chunk.
</p>
<p>
Unfortunately, some web browsers fail to specify response priorities that lead to best end-user experience.
H2O is capable of detecting such web browsers, and if it does, uses server-driven prioritization; i.e. send responses with certain MIME-types before others.
</p>
<p>
It is possible to tune or turn off server-driven prioritization using directives: <a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>, <a href="configure/http2_directives.html#http2-reprioritize-blocking-assets"><code>http2-reprioritize-blocking-assets</code></a>.
</p>
<p>
See also:
<ul>
<li><a href="benchmarks.html#download-timings">Download Timings Benchmark</a>
<li><a href="http://blog.kazuhooku.com/2015/06/http2-and-h2o-improves-user-experience.html">HTTP/2 (and H2O) improves user experience over HTTP/1.1 or SPDY</a>
</ul>
</p>

<h3 id="server-push">Server push</h3>

<p>
H2O recognizes <code>link</code> headers with <a href="https://w3c.github.io/preload/">preload</a> keyword sent by a backend application server (reverse proxy or FastCGI) or an mruby handler, and pushes the designated resource to a client.
</p>
<?= $ctx->{example}->('A link response header triggering HTTP/2 push', <<'EOT')
link: </assets/jquery.js>; rel=preload
EOT
?>

<p>When the HTTP/2 driver of H2O recognizes a <code>link</code> response header with <code>rel=preload</code> attribute set, and if all of the following conditions are met, the specified resource is pushed to the client.
</p>
<ul>
<li>configuration directive <a href="configure/http2_directives.html#http2-push-preload">http2-push-preload</a> is not set to <code>OFF</code></li>
<li>the <code>link</code> header does not have the <code>nopush</code> attribute set</li>
<li>the <code>link</code> header is <i>not</i> part of a pushed response</li>
<li>the client does not disable HTTP/2 push</li>
<li>number of the pushed responses in-flight is below the negotiated threshold</li>
<li>authority of the resource specified is equivalent to the request that tried to trigger the push</li>
<li>(for handlers that return the status code synchronously) the status code of the response to be pushed does not indicate an error (i.e. 4xx or 5xx)</li>
</ul>
<p>
The server also provides a mechanism to track the clients' cache state via cookies, and to push the resources specified with the <code>link</code> header only when it does not exist within the clients' cache.  For details, please refer to the documentation of <a href="configure/http2_directives.html#http2-casper"><code>http2-casper</code></a> configuration directive.
</p>
<p>
When a resource is pushed, the priority is determined using the <a href="configure/file_directives.html#file.mime.addtypes"><code>priority</code> attribute</a> of the MIME-type configuration.  If the priority is set to <code>highest</code> then the resource will be sent to the client before anything else; otherwise the resource will be sent to client after the main content, as per defined by the HTTP/2 specification.
</p>
<p>
HTTP/1.1 allows a server to send an informational response (see <a href="https://tools.ietf.org/html/rfc7231#section-6.2" target="_blank">RFC 7230 section 6.2</a>) before sending the final response.
Starting from version 2.1, web applications can take advantage of the informational response to initiate HTTP/2 pushes before starting to process the request.
The following example shows how such responses would look like.
</p>
<?= $ctx->{example}->('100 response with link headers', <<'EOT')
HTTP/1.1 100 Continue
Link: </assets/style.css>; rel=preload
Link: </assets/jquery.js>; rel=preload

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!doctype html>
<html>
<head>
<link rel="stylesheet" type="text/css" href="/assets/style.css">
<script type="text/javascript" src="/assets/jquery.js"></scrrpt>
...
EOT
?>
<p>
Pushed responses will have <code>x-http2-push: pushed</code> header set; by looking for the header, it is possible to determine if a resource has been pushed.
It is also possible to log the value in the <a href="configure/access_log_directives.html#access-log">access log</a> by specifying <code>%{x-http2-push}o</code>, push responses but cancelled by CASPER will have the value of the header logged as <code>cancelled</code>.
</p>
<p>
See also:
<ul>
<li><a href="http://blog.kazuhooku.com/2015/12/optimizing-performance-of-multi-tiered.html">Optimizing performance of multi-tier web applications using HTTP/2 push</a>
</ul>
</p>

<h3 id="latency-optimization">Latency Optimization</h3>

<p>
When using HTTP/2, a client often issues high-priority requests (e.g. requests for CSS and JavaScript files that block the rendering) while a lower-priority response (e.g. HTML) is in flight.
In such case, it is desirable for a server to switch to sending the response of the high-priority requests as soon as it observes the requests.
</p>
<p>
In order to do so, send buffer of the TCP/IP stack should be kept empty except for the packets in-flight, and size of the TLS records must be small enough to avoid head-of-line blocking.
The downside is that obeying the requirement increases the interaction between the server process and kernel, which result in consumption of more CPU cycles and slightly increased latency.
</p>
<p>
Starting from version 2.1, H2O provides directives that lets the users tune how the TCP/IP stack is used depending on the observed RTT, CWND, and the additional latency imposed by the interaction between the server and the OS.
</p>
<p>
For TCP/IP connections with greater RTT and smaller CWND than the configured threshold (i.e. a long-distance TCP connection during slow start), the server will try to keep the size of HTTP/2 frames unsent as small as possible so that it can switch to sending a higher-priority response.
Benchmarks suggest that users can expect in average 1 RTT reduction when this optimization is enabled.
For connections that do not meet the criteria, the server will utilize the TCP/IP stack in ordinary ways.
</p>
<p>
The optimization is supported only on Linux and OS X, the two operating systems that provide access to <code>TCP_INFO</code> and an interface to adjust the size of the unsent buffer (<code>TCP_NOTSENT_LOWAT</code>).
</p>
<p>
Please refer to the documentation of the directives below to configure the optimization:
<ul>
<li><a href="configure/http2_directives.html#http2-latency-optimization-min-rtt"><code>http2-latency-optimization-min-rtt</code></a></li>
<li><a href="configure/http2_directives.html#http2-latency-optimization-max-additional-delay"><code>http2-latency-optimization-max-additional-delay</code></a></li>
<li><a href="configure/http2_directives.html#http2-latency-optimization-max-cwnd"><code>http2-latency-optimization-max-cwnd</code></a></li>
</ul>
</p>

<p>
The following describes the configuration directives for controlling the HTTP/2 protocol handler.
</p>

<?
$ctx->{directive}->(
    name    => "http2-casper",
    levels  => [ qw(global host) ],
    default => "http2-casper: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>,
<a href="https://github.com/h2o/h2o/issues/421">issue #421</a>
EOT
    desc    => <<'EOT',
Configures CASPer (cache-aware server-push).
EOT
)->(sub {
?>
<p>
When enabled, H2O maintains a fingerprint of the web browser cache, and cancels server-push suggested by the handlers if the client is known to be in possession of the content.
The fingerprint is stored in a cookie named <code>h2o_casper</code> using <a href="https://www.imperialviolet.org/2011/04/29/filters.html">Golomb-compressed sets</a> (a compressed encoding of <a href="https://en.wikipedia.org/wiki/Bloom_filter">Bloom filter</a>).
</p>
<p>
If the value is <code>OFF</code>, the feature is disabled.
Push requests (made by the handlers through the use of <code>Link: rel=preload</code> header) are processed regardless of whether if client already has the responses in its cache.
If the value is <code>ON</code>, the feature is enabled with the defaults value specified below.
If the value is mapping, the feature is enabled, recognizing the following attributes.
<dl>
<dt>capacity-bits:
<dd>number of bits used for the fingerprinting.
Roughly speaking, the number of bits should be <code>log2(1/P * number-of-assets-to-track)</code> where P being the probability of false positives.
Default is <code>13</code>, enough for tracking about 100 asset files with 1/100 chance of false positives (i.e. <code>log2(100 * 100) =~ 2<sup>13</code>).
<dt>tracking-types:
<dd>specifies the types of the content tracked by casper.
If omitted or set to <code>blocking-assets</code>, maintains fingerprint (and cancels server push) for resources with mime-type of <a href="configure/file_directives.html#file.mime.addtypes"><code>highest</code></a> priority.
If set to <code>all</code>, tracks all responses.
</dl>
</p>
It should be noted that the size of the cookie will be <code>log2(P) * number-of-assets-being-tracked</code> bits multiplied by the overhead of Base 64 encoding (<code>4/3</code>).
Therefore with current cookie-based implementation, it is necessary in many cases to restrict the resources being tracked to those have significant effect to user-perceived response time.
</p>

<?= $ctx->{example}->('Enabling CASPer', <<'EOT')
http2-casper: ON

# `ON` is equivalent to:
# http2-casper:
#   capacity-bits:  13
#   tracking-types: blocking-assets
EOT
?>

? });

<?
my $spec_url = "https://tools.ietf.org/html/draft-benfield-http2-debug-state-01";
$ctx->{directive}->(
    name    => "http2-debug-state",
    levels  => [ qw(host) ],
    see_also => render_mt(<<"EOT"),
<a href=\"$spec_url\">HTTP/2 Implementation Debug State (draft-01)</a>
EOT
    desc    => <<"EOT",
A directive to turn on the <a href=\"$spec_url\">HTTP/2 Implementation Debug State</a>.
EOT
)->(sub {
?>

<p>
This experimental feature serves a JSON document at the fixed path <code>/.well-known/h2/state</code>, which describes an internal HTTP/2 state of the H2O server.
To know the details about the response fields, please see <a href="<?= $spec_url ?>">the spec</a>.
This feature is only for developing and debugging use, so it's highly recommended that you disable this setting in the production environment.
</p>

<p>
The value of this directive specifies the property set contained in the response. Available values are <code>minimum</code> or <code>hpack</code>.
If <code>hpack</code> is specified, the response will contain the internal hpack state of the same connection.
If <code>minimum</code> is specified, the response doesn't contain the internal hpack state.
</p>

<p>
In some circumstances, there may be a risk of information leakage on providing an internal hpack state. For example, the case that some proxies exist between the client and the server, and they share the connections among the clients.
Therefore, you should specify <code>hpack</code> only when the server runs in the environments you can completely control.
</p>

<p>
This feature is considered experimental yet.
For now, the implementation conforms to the version draft-01 of the specification.
</p>

? });

<?
$ctx->{directive}->(
    name    => "http2-idle-timeout",
    levels  => [ qw(global) ],
    default => 'http2-idle-timeout: 10',
    desc    => <<'EOT',
Timeout for idle connections in seconds.
EOT
)->(sub {});

$ctx->{directive}->(
    name    => "http2-max-concurrent-requests-per-connection",
    levels  => [ qw(global) ],
    default => 'http2-max-concurrent-requests-per-connection: 100',
    desc    => <<'EOT',
Maximum number of requests to be handled concurrently within a single HTTP/2 connection.
EOT
)->(sub {
?>
<p>
The value cannot exceed 256.
</p>
? })

<?
$ctx->{directive}->(
    name    => "http2-latency-optimization-min-rtt",
    levels  => [ qw(global) ],
    since   => '2.1',
    default => 'http2-latency-optimization-min-rtt: 50',
    desc    => << 'EOT',
Minimum RTT (in milliseconds) to enable <a href="configure/http2_directives.html#latency-optimization">latency optimization</a>.
EOT
)->(sub {
?>
<p>
Latency optimization is disabled for TCP connections with smaller RTT (round-trip time) than the specified value.
Otherwise, whether if the optimization is used depends on other parameters.
</p>
<p>
Setting this value to 4294967295 (i.e. <code>UINT_MAX</code>) effectively disables the optimization.
</p>
? })

<?
$ctx->{directive}->(
    name    => "http2-latency-optimization-max-additional-delay",
    levels  => [ qw(global) ],
    since   => '2.1',
    default => 'http2-latency-optimization-max-additional-delay: 0.1',
    desc    => << 'EOT',
Maximum additional delay (as the ratio to RTT) permitted to get <a href="configure/http2_directives.html#latency-optimization">latency optimization</a> activated.
EOT
)->(sub {
?>
<p>
Latency optimization is disabled if the additional delay imposed by the interaction between the OS and the TCP/IP stack is estimated to be greater than the given threshold.
Otherwise, whether if the optimization is used depends on other parameters.
</p>
? })

<?
$ctx->{directive}->(
    name    => "http2-latency-optimization-max-cwnd",
    levels  => [ qw(global) ],
    since   => '2.1',
    default => 'http2-latency-optimization-max-cwnd: 65535',
    desc    => << 'EOT',
Maximum size (in octets) of CWND to get <a href="configure/http2_directives.html#latency-optimization">latency optimization</a> activated.
EOT
)->(sub {
?>
<p>
CWND is a per-TCP-connection variable that represents the number of bytes that can be sent within 1 RTT.
</p>
<p>
The server will not use or stop using latency optimization mode if CWND becomes greater than the configured value.
In such case, average size of HTTP/2 frames buffered unsent will be slightly above the <a href="https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt" target="_blank"><code>tcp_notsent_lowat</code></a> sysctl value.
</p>
?>
? })

<?
$ctx->{directive}->(
    name    => "http2-push-preload",
    levels  => [ qw(global host) ],
    since   => '2.1',
    default => 'http2-push-preload: ON',
    desc    => << 'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether if the server should push resources when observing a <code>link: rel=preload</code> header.
EOT
)->(sub {
?>
? })

<?
$ctx->{directive}->(
    name    => "http2-reprioritize-blocking-assets",
    levels  => [ qw(global) ],
    default => 'http2-reprioritize-blocking-assets: ON',
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>,
<a href="http://blog.kazuhooku.com/2015/06/http2-and-h2o-improves-user-experience.html">HTTP/2 (and H2O) improves user experience over HTTP/1.1 or SPDY</a>
EOT
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating if the server should send contents with <code>highest</code> priority before anything else.
EOT
)->(sub {
?>
<p>
To maximize the user-perceived responsiveness of a web page, it is essential for the web server to send blocking assets (i.e. CSS and JavaScript files in <code>&lt;HEAD&gt;</code>) before any other files such as images.
HTTP/2 provides a way for web browsers to specify such priorities to the web server.
However, as of Sep. 2015, no major web browsers except Mozilla Firefox take advantage of the feature.
</p>
<p>
This option, when enabled, works as a workaround for such web browsers, thereby improving experience of users using the web browsers.
</p>
<p>
Technically speaking, it does the following:
<ul>
<li>if the client uses dependency-based prioritization, do not reprioritize
<li>if the client does not use dependency-based prioritization, send the contents of which their types are given <a href="configure/file_directives.html#file.mime.addtypes"><code>highest</code></a> priority before any other responses
</ul>
</p>
? });

? })
