? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Syntax and Structure")->(sub {

<h3>Syntax</h3>

<p>
H2O uses <a href="http://www.yaml.org/">YAML</a> 1.1 as the syntax of its configuration file.
</p>

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
Certain configuration directives can be used in more than one levels.  For example, the <a href="configure/base_directives.html#listen"><code>listen</code></a> can be used either at the global level or at the host level.
<a href="configure/expires_directives.html#expires"><code>Expires</code></a> can be used at all levels.
On the other hand <a href="configure/file_directives.html#file.dir"><code>file.dir</code></a> can only be used at the path level.
</p>

<h3 id="path-level">Path-level configuration</h3>

<p>
Values of the path-level configuration define the action(s) to be taken when the server processes a request that prefix-matches to the configured paths.
Each entry of the mapping associated to the paths is evaluated in the order they appear.
</p>

<p>
Consider the following example.
When receiving a request for <code>https://example.com/foo</code>, <a href="configure/file_directives.html">the file handler</a> is first executed trying to serve a file named <code>/path/to/doc-root/foo</code> as the response.
In case the file does not exist, then <a href="configure/fastcgi_directives.html">the FastCGI handler</a> is invoked.
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
        file.dir: /path/to/doc-root
        fastcgi.connect:
          port: /path/to/fcgi.sock
          type: unix
EOT
?>

<p>
Starting from version 2.1, it is also possible to define the path-level configuration as a sequence of mappings instead of a single mapping.
The following example is identical to the previous one.
Notice the dashes placed before the handler directives.
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
        - file.dir: /path/to/doc-root
        - fastcgi.connect:
            port: /path/to/fcgi.sock
            type: unix
EOT
?>

<h3 id="yaml_alias">Using YAML Alias</h3>

<p>
H2O resolves <a href="http://yaml.org/YAML_for_ruby.html#aliases_and_anchors">YAML aliases</a> before processing the configuration file.
Therefore, it is possible to use an alias to reduce the redundancy of the configuration file.
For example, the following configuration reuses the first <code>paths</code> element (that is given an anchor named <code>default_paths</code>) in the following definitions.

<?= $ctx->{code}->(<< 'EOT')
hosts:
  "example.com":
    listen:
      port: 443
      ssl:
        certificate-file: /path/to/example.com.crt
        key-file:         /path/to/example.com.crt
    paths: &default_paths
      "/":
        file.dir: /path/to/doc-root
  "example.org":
    listen:
      port: 443
      ssl:
        certificate-file: /path/to/example.org.crt
        key-file:         /path/to/example.org.crt
    paths: *default_paths
EOT
?>

<h3 id="yaml_merge">Using YAML Merge</h3>

<p>
Since version 2.0, H2O recognizes <a href="http://yaml.org/type/merge.html">Merge Key Language-Independent Type for YAML&trade; Version 1.1</a>.
Users can use the feature to merge an existing mapping against another.
The following example reuses the TLS configuration of <code>example.com</code> in <code>example.org</code>.
</p>

<?= $ctx->{code}->(<< 'EOT')
hosts:
  "example.com":
    listen:
      port: 443
      ssl: &default_ssl
        minimum-version: TLSv1.2
        cipher-suite: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
        certificate-file: /path/to/example.com.crt
        key-file:         /path/to/example.com.crt
    paths:
      ...
  "example.org":
    listen:
      port: 443
      ssl:
        <<: *default_ssl
        certificate-file: /path/to/example.org.crt
        key-file:         /path/to/example.org.crt
    paths:
      ...
EOT
?>

<h3 id="including_files">Including Files</h3>

<p>
Starting from version 2.1, it is possible to include a YAML file from the configuration file using <code>!file</code> custom YAML tag.
The following example extracts the TLS configuration into <code>default_ssl.conf</code> and include it multiple times in <code>h2o.conf</code>.
</p>

<?= $ctx->{example}->('default_ssl.conf', << 'EOT')
minimum-version: TLSv1.2
cipher-suite: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
certificate-file: /path/to/example.com.crt
key-file:         /path/to/example.com.crt
EOT
?>

<?= $ctx->{example}->('h2o.conf', << 'EOT')
hosts:
  "example.com":
    listen:
      port: 443
      ssl: !file default_ssl.conf
    paths:
      ...
  "example.org":
    listen:
      port: 443
      ssl:
        <<: !file default_ssl.conf
        certificate-file: /path/to/example.org.crt
        key-file:         /path/to/example.org.crt
    paths:
      ...
EOT
?>

? })
