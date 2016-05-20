? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Using CGI")->(sub {

<p>
Starting from version 1.7, H2O comes with a FastCGI-to-CGI gateway (<code>fastcgi-cgi</code>), which can be found under <code>share/h2o</code> directory of the installation path.
The gateway can be used for running CGI scripts through the FastCGI handler.
</p>

<p>
The example below maps <code>.cgi</code> files to be executed by the gateway.
It is also possible to run CGI scripts under different privileges by specifying the <code>user</code> attribute of the directive.
</p>

<?= $ctx->{example}->('Execute <code>.cgi</code> files using FastCGI-to-CGI gateway', <<'EOT');
file.custom-handler:
  extension: .cgi
  fastcgi.spawn:
    command: "exec $H2O_ROOT/share/h2o/fastcgi-cgi"
EOT
?>

The gateway also provides options to for tuning the behavior.  A full list of options can be obtained by running the gateway directly with <code>--help</code> option.

<?= $ctx->{example}->('Output of <code>share/h2o/fastcgi-cgi --help</code>', <<'EOT');
$ share/h2o/fastcgi-cgi --help
Usage:
    share/h2o/fastcgi-cgi [options]

Options:
  --listen=sockfn    path to the UNIX socket.  If specified, the program will
                     create a UNIX socket at given path replacing the existing
                     file (should it exist).  If not, file descriptor zero (0)
                     will be used as the UNIX socket for accepting new
                     connections.
  --max-workers=nnn  maximum number of CGI processes (default: unlimited)
  --pass-authz       if set, preserves HTTP_AUTHORIZATION parameter
EOT
?>

? })
