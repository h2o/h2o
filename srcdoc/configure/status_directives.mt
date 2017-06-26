? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Status Directives")->(sub {

<p>
The status handler exposes the current states of the HTTP server.
This document describes the configuration directives of the handler.
</p>

<?
$ctx->{directive}->(
    name    => "status",
    levels  => [ qw(path) ],
    since   => '2.0',
    desc    => <<'EOT',
If the argument is <code>ON</code>, the directive registers the status handler to the current path.
EOT
)->(sub {
?>
<p>
Access to the handler should be <a href="configure/mruby.html#access-control">restricted</a>, considering the fact that the status includes the details of in-flight HTTP requests.
The example below uses <a href="configure/basic_auth.html">Basic authentication</a>.
</p>
<?= $ctx->{example}->("Exposing status with Basic authentication", <<'EOT');
paths:
  /server-status:
    mruby.handler: |
      require "htpasswd.rb"
      Htpasswd.new("/path/to/.htpasswd", "status")
    status: ON
EOT
?>
<p>
The information returned by the <code>/json</code> handler can be filtered out using the optional <code>show=module1,module2</code> parameter.
There are currently three modules defined:
<ul>
<li><code>requests</code>: displays the requests currently in-flight.</li>
<li><code>durations</code>: displays durations statistics for requests since server start time in seconds (returns all zeros unless <code>duration-stats</code> is <code>ON</code>).</li>
<li><code>errors</code>: displays counters for internally generated errors.</li>
<li><code>main</code>: displays general daemon-wide stats.</li>
</ul>
</p>
? })

<?
$ctx->{directive}->(
    name    => "duration-stats",
    levels  => [ qw(global) ],
    since   => '2.1',
    default => 'duration-stats: OFF',
    desc    => q{Gather timing stats for requests.},
)->(sub {
?>
</p>
<p>
If the argument is <code>ON</code>, this directive populates duration statistics in seconds, to be consumed by status handlers.
Enabling this feature has a noticeable CPU and memory impact.
</p>
<p>
Note that the time spent while processing a request in a blocking manner (such as opening a file or a mruby handler that does invoke a network operation) will not be reflected to the <code>process_time</code> element of the duration stats due to the fact that the timer being used for measuring the time spent is updated only once per loop.
</p>
? })

? })
