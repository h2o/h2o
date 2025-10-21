? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Compress Directives")->(sub {

<p>
The compress handler performs on-the-fly compression - it compresses the contents of an HTTP response as it is being sent, if the client indicates itself to be capable of decompressing the response transparently with the use of <a href="https://tools.ietf.org/html/rfc7231#section-5.3.4"><code>Accept-Encoding</code></a> header</li>, and if the response is deemed compressible according to the following rules.
</p>
<p>
If <code>x-compress-hint</code> response header does not exist or the value is <code>auto</code>, then whether if the response is considered compressible depends on the <code>is_compressible</code> attribute assigned to the content type (see <a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>).
If <code>x-compress-hint</code> response header exists and the value is <code>on</code>, the response is always considered to be compressible.
If the value of the response header is set to <code>off</code>, then the response never gets compressed.
</p>

<p>
The following are the  configuration directives recognized by the handler.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name     => "compress",
    levels   => [ qw(global host path extension) ],
    default  => "compress: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/file_directives.html#file.send-compressed"><code>file.send-compressed</code></a>, <a href="configure/file_directives.html#file.mime.addtypes"><code>file.mime.addtypes</code></a>
EOT
    since    => '2.0',
    desc     => <<'EOT',
Enables on-the-fly compression of HTTP response.
EOT
)->(sub {
?>
<p>
If the argument is <code>ON</code>, <a href="https://datatracker.ietf.org/doc/draft-alakuijala-brotli/">brotli</a>, <a href="https://www.rfc-editor.org/rfc/rfc8878.html">zstd</a>, and <a href="https://tools.ietf.org/html/rfc1952">gzip</a> compression are enabled.
If the argument is <code>OFF</code>, on-the-fly compression is disabled.
If the argument is a sequence, the elements are the list of compression algorithms to be enabled.
If the argument is a mapping, each key specifies the compression algorithm to be enabled, and the values specify the quality of the algorithms (gzip: 1&ndash;9, br: 0&ndash;11, zstd: 1&ndash;22). When omitted, the default qualities are 1 for gzip, 1 for brotli, and 3 for zstd.
</p>
<p>
When multiple algorithms are enabled and the client supports several, H2O prefers brotli, then zstd, then gzip.
</p>
<?= $ctx->{example}->('Enabling on-the-fly compression', <<'EOT')
# enable all algorithms
compress: ON

# enable by name
compress: [ gzip, br, zstd ]

# enable gzip only
compress: [ gzip ]

# tune zstd quality
compress:
  zstd: 7
EOT
?>
? })

<?
$ctx->{directive}->(
    name     => "compress-minimum-size",
    levels   => [ qw(global host path extension) ],
    default  => "compress-minimum-size: 100",
    since    => '2.0',
    desc     => <<'EOT',
Defines the minimum size a files needs to have in order for H2O to compress the request.
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name     => "gzip",
    levels   => [ qw(global host path extension) ],
    default  => "gzip: OFF",
    see_also => render_mt(<<'EOT'),
<a href="configure/compress_directives.html#compress"><code>compress</code></a>
EOT
    since    => '1.5',
    desc     => <<'EOT',
Enables on-the-fly compression of HTTP response using gzip.
EOT
)->(sub {
?>
Equivalent to <code>compress: [ gzip ]</code>.
? })

? })

? })
