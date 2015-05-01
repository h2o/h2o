? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "HTTP/1 Directives")->(sub {

<p>
This document describes the configuration directives for controlling the HTTP/1 protocol handler.
</p>

<?
$ctx->{directive}->(
    name    => "http1-request-timeout",
    levels  => [ qw(global) ],
    default => 'http1-request-timeout: 10',
    desc    => q{Timeout for incoming requests in seconds.},
)->(sub {});

$ctx->{directive}->(
    name    => "http1-upgrade-to-http2",
    levels  => [ qw(global) ],
    default => 'http1-upgrade-to-http2: ON',
    desc    => q{Boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not to allow upgrade to HTTP/2.},
)->(sub {});
?>

? })
