? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt")->(sub {

<title>Command Options - Configure - H2O</title>

?= $_mt->render_file("header.mt")

<div id="main">

<h2>Configure &gt; Command Options</h2>

<p>
Full list of command options can be viewed by running <code>h2o --help</code>.
Following is the output of <code>--help</code> as of version 1.2.0.
</p>

<?= $ctx->{code}->(<< 'EOT')
Options:
  -c, --conf FILE    configuration file (default: h2o.conf)
  -m, --mode <mode>  specifies one of the following mode
                     - worker: invoked process handles incoming connections
                               (default)
                     - daemon: spawns a master process and exits. `error-log`
                               must be configured when using this mode, as all
                               the errors are logged to the file instead of
                               being emitted to STDERR
                     - master: invoked process becomes a master process (using
                               the `share/h2o/start_server` command) and spawns
                               a worker process for handling incoming
                               connections. Users may send SIGHUP to the master
                               process to reconfigure or upgrade the server.
                     - test:   tests the configuration and exits
  -t, --test         synonym of `--mode=test`
  -v, --version      prints the version number
  -h, --help         print this help
EOT
?>

</div>

? })
