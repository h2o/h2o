? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Errordoc Directives")->(sub {

<p>
This document describes the configuration directives of the errordoc handler.
</p>

<?
$ctx->{directive}->(
    name    => "error-doc",
    levels  => [ qw(global host path extension) ],
    desc    => <<'EOT',
Specifies the content to be sent when returning an error response (i.e. a response with 4xx or 5xx status code).
EOT
)->(sub {
?>
<p>
The argument must be a mapping containing following attributes, or if it is a sequence, every element must be a mapping with the following attributes.
<ul>
<li><code>status</code> - three-digit number indicating the status code
<li><code>url</code> - URL of the document to be served
</ul>
</p>
<p>
URL can either be absolute or relative.
Only <code>content-type</code>, <code>content-language</code>, <code>set-cookie</code> headers obtained from the specified URL are served to the client.
</p>
<p>
<?= $ctx->{example}->('Set error document for 404 status', <<'EOT')
error-doc:
  status: 404
  url: /404.html
EOT
?>
<?= $ctx->{example}->('Set error document for 500 and 503 status', <<'EOT')
error-doc:
  - status: 500
    url: /internal-error.html
  - status: 503
    url: /service-unavailable.html
EOT
?>
</p>
? })

? })
