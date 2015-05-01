? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Redirect Directives")->(sub {

<p>
This document describes the configuration directives of the redirect handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "redirect",
    levels  => [ qw(path) ],
    desc    => <<'EOT',
<p>
Redirects the requests to given URL.
</p>
<p>
If the argument is a scalar, the value is considered as the URL to where the requests should be redirected.
If the argument is a mapping, the <code>url</code> property is considered the URL, and the <code>status</code> property indicates the status code to be used for the redirect response.
</p>
<p>
The directive rewrites the URL by replacing the host and path part of the URL at which the directive is used with the given URL.  For example, when using the configuration below, requests to <code>http://example.com/abc.html</code> will be redirected to <code>https://example.com/abc.html</code>.
</p>
<div class="example">
<div class="caption">Example. Redirect all HTTP to HTTPS permanently (except for the files under <code>RSS</code>)</div>
<pre><code>hosts:
    "example.com:80":
        paths:
            "/":
                redirect:
                    status: 301
                    url:    "https://example.com/"
            "/rss":
                file.dir: /path/to/rss
</code></pre>
</div>
EOT
}) ?>

? })
