? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Redirect Directives")->(sub {

<p>
This document describes the configuration directives of the redirect handler.
</p>

<?
$ctx->{directive}->(
    name      => "redirect",
     levels    => [ qw(path) ],
     desc      => q{Redirects the requests to given URL.},
)->(sub {
?>
<p>
The directive rewrites the URL by replacing the host and path part of the URL at which the directive is used with the given URL.  For example, when using the configuration below, requests to <code>http://example.com/abc.html</code> will be redirected to <code>https://example.com/abc.html</code>.
</p>
<p>
If the argument is a scalar, the value is considered as the URL to where the requests should be redirected.
</p>
<p>
Following properties are recognized if the argument is a mapping.
<dl>
<dt><code>url</code>
<dd>URL to redirect to
<dt><code>status</code>
<dd>the three-digit status code to use (e.g. <code>301</code>)
<dt><code>internal</code>
<dd>either <code>YES</code> or <code>NO</code> (default); if set to <code>YES</code>, then the server performs an internal redirect and return the content at the redirected URL
</dl>
</p>
<?= $ctx->{example}->('Redirect all HTTP to HTTPS permanently (except for the files under <code>RSS</code>)', <<'EOT');
hosts:
    "example.com:80":
        paths:
            "/":
                redirect:
                    status: 301
                    url:    "https://example.com/"
            "/rss":
                file.dir: /path/to/rss
EOT
?>

? })

? })
