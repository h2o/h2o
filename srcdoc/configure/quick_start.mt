? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Quick Start")->(sub {

<p>
In order to run the H2O standalone HTTP server, you need to write a configuration file.
The minimal configuration file looks like as follows.
</p>

<?= $ctx->{code}->(<< 'EOT')
hosts:
  "myhost.example.com":
    listen:
      port: 80
    listen:
      port: 443
      ssl: {}
    listen:
    　port: 443
      ssl: {}
      type: quic
    paths:
      /:
        file.dir: /path/to/the/public-files

user: nobody
access-log: /path/to/the/access-log
error-log: /path/to/the/error-log
pid-file: /path/to/the/pid-file

acme:
  email: admin@myhost.example.com
  accept-tos: YES
EOT
?>

<p>
The configuration instructs the server to:
<ol>
<li>serve contents under the hostname: <code>myhost.example.com</code></li>
<li>for HTTP, listen on TCP port 80</li>
<li>for HTTPS, listen on TCP port 443 and UDP port 443</li>
<li>serve files under <code>/path/to/the/public-files</code></li>
<li>run under the privileges of <code>nobody</code></li>
<li>emit access logs to file: <code>/path/to/the/access-log</code></li>
<li>emit error logs to <code>/path/to/the/error-log</code></li>
<li>store the process id of the server in <code>/path/to/the/pid-file</code>
<li>use ACME to fetch the TLS certificates automatically (note: lego must be installed for this to work).</li>
</ol>
</p>

<p>
Enter the command below to start the server.
</p>

<?= $ctx->{code}->(<< 'EOT')
% sudo h2o -m daemon -c /path/to/the/configuration-file
EOT
?>

<p>
The command instructs the server to read the configuration file, and start in <code>daemon</code> mode, which dispatches a pair of master and worker processes that serves the HTTP requests.
</p>

<p>
To stop the server, send <code>SIGTERM</code> to the server.
</p>

<?= $ctx->{code}->(<< 'EOT')
% sudo kill -TERM `cat /path/to/the/pid-file`
EOT
?>

<h3>Next Step</h3>

<p>
Now that you know how to start and stop the server, the next step is to learn the <a href="configure.html">configuration directives and their structure</a>, or see <a href="https://github.com/h2o/h2o/wiki#configuration-examples">the configuration examples</a>.
</p>

</p>

? })
