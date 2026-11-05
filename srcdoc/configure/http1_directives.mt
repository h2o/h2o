? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/1 Directives")->(sub {

<p>
This document describes the configuration directives for controlling the HTTP/1 protocol handler.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name    => "http1-request-timeout",
    levels  => [ qw(global) ],
    default => 'http1-request-timeout: 10',
    desc    => q{Timeout for incoming requests in seconds.},
)->(sub {});

$ctx->{directive}->(
    name    => "http1-request-io-timeout",
    levels  => [ qw(global) ],
    default => 'http1-request-io-timeout: 5',
    desc    => q{Timeout for incoming request I/O in seconds.},
)->(sub {});

$ctx->{directive}->(
    name    => "http1-request-io-timeout-while-generating",
    levels  => [ qw(global) ],
    default => 'http1-request-io-timeout-while-generating: ON',
    desc    => q{Boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether <code>http1-request-io-timeout</code> also applies while waiting for the response to be generated.},
)->(sub {
?>
<p>
When set to <code>OFF</code>, the timeout covers reading the request and each write of the response, but not the time between writes during which the response is being generated.
This allows streamed responses that stay idle for long periods, such as Server-Sent Events, to be served without closing their connections after <code>http1-request-io-timeout</code>.
</p>
? })

$ctx->{directive}->(
    name    => "http1-upgrade-to-http2",
    levels  => [ qw(global) ],
    default => 'http1-upgrade-to-http2: ON',
    desc    => q{Boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not to allow upgrade to HTTP/2.},
)->(sub {});
?>

? })

? })
