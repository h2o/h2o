? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "File Directives")->(sub {

<p>
This document describes the configuration directives of the file handler - a handler that for serving static files.
</p>
<p>
Two directives: <a href="configure/file_directives.html#file.dir"><code>file.dir</code></a> and <a href="configure/file_directives.html#file.file"><code>file.file</code></a> are used to define the mapping.
Other directives modify the behavior of the mappings defined by the two.
</p>

<?
$ctx->{directive}->(
    name    => "file.custom-handler",
    levels  => [ qw(global host path) ],
    desc    => q{The directive maps extensions to a custom handler (e.g. FastCGI).},
)->(sub {
?>
<p>
The directive accepts a mapping containing configuration directives that can be used at the <code>extension</code> level, together with a property named <code>extension</code> specifying a extension (starting with <code>.</code>) or a sequence of extensions to which the directives should be applied.
Only one handler must exist within the directives.
</p>
<?= $ctx->{example}->('Mapping PHP files to FastCGI', <<'EOT')
file.custom-handler:
  extension: .php
  fastcgi.connect:
    port: /tmp/fcgi.sock
    type: unix

EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "file.dir",
    levels  => [ qw(path) ],
    desc    => q{The directive specifies the directory under which should be served for the corresponding path.},
    see_also => render_mt(<<EOT),
<a href="configure/file_directives.html#file.dirlisting"><code>file.dirlisting</code></a>,
<a href="configure/file_directives.html#file.file"><code>file.file</code></a>,
<a href="configure/file_directives.html#file.dirlisting"><code>file.index</code></a>
EOT
)->(sub {
?>
<?= $ctx->{example}->('Serving files under different paths', <<'EOT')
paths:
    "/":
        file.dir: /path/to/doc-root
    "/icons":
        file.dir: /path/to/icons-dir
EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "file.dirlisting",
    levels  => [ qw(global host path) ],
    default => 'file.dirlisting: OFF',
    desc    => <<'EOT',
A boolean flag (<code>OFF</code>, or <code>ON</code>) specifying whether or not to send the directory listing in case none of the index files exist.
EOT
    see_also => render_mt(<<EOT),
<a href="configure/file_directives.html#file.dir"><code>file.dir</code></a>
EOT
)->(sub {});

$ctx->{directive}->(
    name    => "file.etag",
    levels  => [ qw(global host path) ],
    default => 'file.etag: ON',
    desc    => <<'EOT',
A boolean flag (<code>OFF</code>, or <code>ON</code>) specifying whether or not to send etags.
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name     => "file.file",
    levels   => [ qw(path) ],
    desc     => q{The directive maps a path to a specific file.},
    see_also => render_mt(<<EOT),
<a href="configure/file_directives.html#file.dir"><code>file.dir</code></a>
EOT
    since    => '2.0',
)->(sub {
?>
<?= $ctx->{example}->('Mapping a path to a specific file', <<'EOT')
paths:
  /robots.txt:
    file.file: /path/to/robots.txt
EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "file.index",
    levels  => [ qw(global host path) ],
    default => "file.index: [ 'index.html', 'index.htm', 'index.txt' ]",
    desc    => q{Specifies the names of the files that should be served when the client sends a request against the directory.},
    see_also => render_mt(<<EOT),
<a href="configure/file_directives.html#file.dir"><code>file.dir</code></a>
EOT
)->(sub {
?>
<p>
The sequence of filenames are searched from left to right, and the first file that existed is sent to the client.
</p>
? })

<?
$ctx->{directive}->(
    name     => "file.mime.addtypes",
    levels   => [ qw(global host path) ],
    see_also => render_mt(<<'EOT'),
<a href="configure/compress_directives.html#compress"><code>compress</code></a>,
<a href="configure/http2_directives.html#http2-casper"><code>http2-casper</code></a>,
<a href="configure/http2_directives.html#http2-reprioritize-blocking-assets"><code>http2-reprioritize-blocking-assets</code></a>
EOT
    desc     => q{The directive modifies the MIME mappings by adding the specified MIME type mappings.},
)->(sub {
?>
<?= $ctx->{example}->('Adding MIME mappings', <<'EOT')
file.mime.addtypes:
    "application/javascript": ".js"
    "image/jpeg": [ ".jpg", ".jpeg" ]
EOT
?>
<p>
The default mappings is hard-coded in <a href="https://github.com/h2o/h2o/blob/master/lib/handler/mimemap/defaults.c.h">lib/handler/mimemap/defaults.c.h</a>.
</p>
<p>
It is also possible to set certain attributes for a MIME type.
The example below maps <code>.css</code> files to <code>text/css</code> type, setting <code>is_compressible</code> flag to <code>ON</code> and <code>priority</code> to highest.
</p>

<?= $ctx->{example}->('Setting MIME attributes', <<'EOT')
file.mime.settypes:
    "text/css":
         extensions: [".css"]
         is_compressible: yes
         priority: highest
EOT
?>

<p>
Following attributes are recognized.
</p>

<table>
<tr><th>Attribute<th>Possible Values<th>Description
<tr><td><code>is_compressible</code><td><code>ON</code>, <code>OFF</code><td>if content is compressible
<tr><td><code>priority</code><td><code>highest<code>, <code>normal</code><td>send priority of the content
</table>

<p>
The <code>priority</code> attribute affects how the HTTP/2 protocol implementation handles the request.
For detail, please refer to the HTTP/2 directives listed in the <i>see also</i> section below.
By default, mime-types for CSS and JavaScript files are the only ones that are given <code>highest</code> priority.
</p>

? })

<?
$ctx->{directive}->(
    name    => "file.mime.removetypes",
    levels  => [ qw(global host path) ],
    desc    => q{Removes the MIME mappings for specified extensions supplied as a sequence of extensions.},
)->(sub {
?>
<?= $ctx->{example}->('Removing MIME mappings', <<'EOT')
file.mime.removetypes: [ ".jpg", ".jpeg" ]
EOT
?>
? })

<?
$ctx->{directive}->(
    name    => "file.mime.setdefaulttype",
    levels  => [ qw(global host path) ],
    default => q{file.mime.setdefaulttype: "application/octet-stream"},
    desc    => q{Sets the default MIME-type that is used when an extension does not exist in the MIME mappings},
)->(sub {})
?>

<?
$ctx->{directive}->(
    name    => "file.mime.settypes",
    levels  => [ qw(global host path) ],
    desc    => q{Resets the MIME mappings to given mapping.},
)->(sub {
?>
<?= $ctx->{example}->('Resetting the MIME mappings to minimum', <<'EOT')
file.mime.settypes:
    "text/html":  [ ".html", ".htm" ]
    "text/plain": ".txt"
EOT
?>
? })

<?
$ctx->{directive}->(
    name     => "file.send-compressed",
    levels   => [ qw(global host path) ],
    default  => q{file.send-compressed: OFF},
    see_also => render_mt(<<'EOT'),
<a href="configure/compress_directives.html#compress"><code>compress</code></a>
EOT
    since   => '2.0',
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not so send <code>.br</code> or <code>.gz</code> variants if possible.
EOT
)->(sub {
?>
<p>
If set to <code>ON</code>, the handler looks for a file with <code>.br</code> or <code>.gz</code> appended and sends the file, if the client is capable of transparently decoding a <a href="https://datatracker.ietf.org/doc/draft-alakuijala-brotli/">brotli</a> or <a href="https://tools.ietf.org/html/rfc1952">gzip</a>-encoded response.
For example, if a client requests a file named <code>index.html</code> with <code>Accept-Encoding: gzip</code> header and if <code>index.html.gz</code> exists, the <code>.gz</code> file is sent as a response together with a <code>Content-Encoding: gzip</code> response header.
</p>
? })

<?
$ctx->{directive}->(
    name     => "file.send-gzip",
    levels   => [ qw(global host path) ],
    desc     => <<'EOT',
Obsoleted in 2.0.
Synonym of <a href="configure/file_directives.html#file.send-compressed"><code>file.send-compressed</code></a>.
EOT
)->(sub {})
?>

? })
