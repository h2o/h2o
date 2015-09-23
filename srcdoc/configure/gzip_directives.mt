? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Gzip Directives")->(sub {

<p>
This document describes the configuration directives of the gzip handler.
</p>

<?
$ctx->{directive}->(
    name     => "gzip",
    levels   => [ qw(global host path extension) ],
    default  => "gzip: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.send-gzip"><code>file.send-gzip</code></a>, <a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>
EOT
    desc     => <<'EOT',
Enables on-the-fly compression of HTTP response.
EOT
)->(sub {
?>
<p>
When set to <code>ON</code>, the handler compresses the content sent to the client using the <a href="https://www.ietf.org/rfc/rfc1952.txt">GZIP</a> content-encoding if all of the following conditions are met:
</p>
<ul>
<li>client has announced its capability of decoding gzipped content via <code>Accept-Encoding</code> header
<li>content (by checking the content-type) is known to be compressible
</ul>
<p>
When set to <code>OFF</code>, the feature is not used.
</p>

<?= $ctx->{example}->('Enabling on-the-fly gzip compression', <<'EOT')
gzip: ON
EOT
?>

? })

? })
