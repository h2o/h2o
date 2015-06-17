? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Syntax and Structure")->(sub {

<h3>Syntax</h3>

H2O uses <a href="http://www.yaml.org/">YAML</a> 1.1 the syntax of its configuration file.

<h3 id="config_levels">Levels of Configuration</h3>

<p>
When using the configuration directives of H2O, it is important to understand that there are four configuration levels: global, host, path, extension.
</p>

<p>
Global-level configurations affect the entire server.
Host-level configurations affect the configuration for the specific hostname (i.e. corresponds to the <a href="http://httpd.apache.org/docs/2.4/vhosts/">&lt;VirtualHost&gt;</a> directive of the Apache HTTP Server).
Path-level configurations only affect the behavior of resources specific to the path.
</p>

<p>
Extension-level configuration affect how files with certain extensions are being served.
For example, it is possible to map files with <code>.php</code> extension to the FastCGI handler running the <code>php-cgi</code> command.
</p>

<p>
Consider the following example.
</p>

<?= $ctx->{code}->(<< 'EOT')
hosts:
  "example.com":
    listen:
      port: 443
      ssl:
        certificate-file: etc/site1.crt
        key-file: etc/site1.key
    paths:
      "/":
        file.dir: htdocs/site1
      "/icons":
        file.dir: icons
        expires: 1 day
  "example.com:80":
    listen:
      port: 80
    paths:
      "/":
        redirect: "https://example.com/"
EOT
?>

<p>
In the example, two host-level configurations exist (under the <code>hosts</code> mapping), each of them listening to different ports.
The first host listens to port 443 using TLS (i.e. HTTPS) using the specified server certificate and key.
It has two path-level configurations, one for <code>/</code> and the other for <code>/icons</code>, each of them pointing to different local directories containing the files to be served.
The latter also has the <code>expires</code> directive set, so that <code>Cache-Control: max-age=86400</code><?= $ctx->{note}->("1 day is equivalent to 86400 seconds") ?> header would be sent.
The second host accepts connections on port 80 (via the plain-text HTTP protocol), and redirects all the requests to the first host using HTTPS.
</p>

<p>
Certain configuration directives can be used in more than one levels.  For example, the <code>listen</code> directive can be used either at the global level or at the host level.
<code>Expires</code> can be used at all levels.
On the other hand <code>file.dir</code> can only be used at the path level.
</p>

? })
