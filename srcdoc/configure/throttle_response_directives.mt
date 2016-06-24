? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Throttle Response Directives")->(sub {

<p>
The throttle response handler performs per response traffic throttling, when an <code>X-Traffic</code> header exists in the response headers.
</p>
<p>
The value of <code>X-Traffic</code> header should be an integer that represents the speed you want in bytes per second. This header CAN be set with <a href="configure/headers_directives.html#header.add"><code>header.add</code></a> so that traffic for static assets can also be easily throttled.
</p>
<p>
The following are the configuration directives recognized by the handler.
</p>

<?
$ctx->{directive}->(
    name     => "throttle-response",
    levels   => [ qw(global host path extension) ],
    default  => "throttle-response: OFF",
    since    => '2.1',
    desc     => <<'EOT',
Enables traffic throttle per HTTP response.
EOT
)->(sub {
?>
<p>
If the argument is <code>ON</code>, the traffic per response is throttled as long as a legal <code>X-Traffic</code> header exists.
If the argument is <code>OFF</code>, traffic throttle per response is disabled.
</p>
<?= $ctx->{example}->('Enabling traffic throttle per response with static file configuration', <<'EOT')
# enable throttle
throttle-response: ON

# an example host configuration that throttle traffic to ~100KB/s
hosts:
  default:
    paths:
      /:
        file.dir: /path/to/assets
        header.add: "X-Traffic: 100000"
EOT
?>
? })

? })
