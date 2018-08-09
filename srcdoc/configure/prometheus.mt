? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using the Prometheus exporter")->(sub {

<p>
Starting from version 2.3, H2O comes with a mruby script named <a href="https://github.com/h2o/h2o/blob/master/share/h2o/mruby/prometheus_helper.rb">prometheus_helper.rb</a> that allows to export stats in a way compatible with the Prometheus stats aggregator.
</p>

<h3 id="basic-usage">Basic Usage</h3>

<p>
Below example uses the mruby script export a Prometheus endpoint:
</p>

<?= $ctx->{example}->('Prometheus exporter', <<'EOT');
listen: 8080
hosts:
  "*":
    paths:
      /:
        file.dir: examples/doc_root
      /status:
        status: ON
      /metrics:
        mruby.handler: |
          Proc.new do |env|
            require "prometheus_helper.rb"
            PrometheusHelper.run("http://127.0.0.1:8080/status/json")
          end
    access-log: /dev/stdout
EOT
?>


? })
