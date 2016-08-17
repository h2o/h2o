? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using DoS Detection")->(sub {

<p>
Starting from version 2.1, H2O comes with a mruby script named <a href="https://github.com/h2o/h2o/blob/master/share/h2o/mruby/dos_detector.rb">dos_detector.rb</a> that implements DoS Detection feature.
The script provides a Rack handler that detects HTTP flooding attacks based on the client's IP address. 
</p>

<h3 id="basic-usage">Basic Usage</h3>

<p>
Below example uses the mruby script to detect DoS attacks.
The default detecting strategy is simply counting requests within configured period.
If the count exceeds configured threshold, the handler returns a <code>403 Forbidden</code> response.
Otherwise, the handler returns a <code>399</code> response, and the request is <a href="configure/mruby.html#delegating-request">delegated</a> internally to the next handler.
</p>

<?= $ctx->{example}->('Configuring DoS Detection', <<'EOT');
paths:
  "/":
    mruby.handler: |
      require "dos_detector.rb"
      DoSDetector.new({
        :strategy => DoSDetector.CountingStrategy.new({
          :period     => 10,  # default
          :threshold  => 100, # default
          :ban_period => 300, # default
        }),
      })
    file.dir: /path/to/doc_root
EOT
?>

<p>
In the example above, the handler countup the requests within 10 seconds for each IP address, and when the count exceeds 100,
it returns a <code>403 Forbidden</code> response for the request and marks the client as "Banned" for 300 seconds. While marked as "Banned", the handler returns a <code>403 Forbidden</code> to all requests from the same IP address.
</p>

<h3 id="configuring-details">Configuring Details</h3>

<p>
You can pass the following parameters to <code>DoSDetector.new</code> .
<ul>
<li><code>:strategy</code>
  <p>The algorithm to detect DoS attacks. You can write and pass your own strategies if needed. The default strategy is <code>DoSDetector.CountingStrategy</code> which takes the following parameters:</p>
  <ul>
    <li><code>:period</code>
      <p>Time window in seconds to count requests. The default value is 10.</p>
    </li>
    <li><code>:threshold</code>
      <p>Threshold count of request. The default value is 100.</p>
    </li>
    <li><code>:ban_period</code>
      <p>Duration in seconds in which "Banned" client continues to be restricted. The default value is 300.</p>
    </li>
  </ul>
</li>
<li><code>:callback</code>
  <p>The callback which is called by the handler with detecting result. You can define your own callback to return arbitrary response, set response headers, etc. The default callback returns <code>403 Forbidden</code> if DoS detected, otherwise delegate the request to the next handler.</p>
</li>
<li><code>:forwarded</code>
  <p>
    If set true, the handler uses X-HTTP-Forwarded-For header to get client's IP address if the header exists. The default value is true.
  </p>
</li>
<li><code>:cache_size</code>
  <p>
    The capacity of the LRU cache which preserves client's IP address and associated request count. The default value is 128.
  </p>
</li>
</ul>
<?= $ctx->{example}->('Configuring Details', <<'EOT');
paths:
  "/":
    mruby.handler: |
      require "dos_detector.rb"
      DoSDetector.new({
        :strategy => DoSDetector.CountingStrategy.new,
        :forwarded => false,
        :cache_size => 2048,
        :callback => proc {|env, detected, ip|
          if detected && ! ip.start_with?("192.168.")
            [503, {}, ["Service Unavailable"]]
          else
            [399, {}, []]
          end
        }
      })
    file.dir: /path/to/doc_root
EOT
?>
</p>

<h3 id="points-to-notice">Points to Notice</h3>
<ul>
<li>
  For now, counting requests is "per-thread" and not shared between multiple threads.
</li>
</ul>

? })
