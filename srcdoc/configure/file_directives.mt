? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "File Directives")->(sub {

<p>
This document describes the configuration directives of the file handler.
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
    name    => "file.index",
    levels  => [ qw(global host path) ],
    default => "file.index: [ 'index.html', 'index.htm', 'index.txt' ]",
    desc    => q{Specifies the names of the files that should be served when the client sends a request against the directory.},
)->(sub {
?>
<p>
The sequence of filenames afer search from left to right, and the first file that existed is sent to the client.
</p>
? })

<?
$ctx->{directive}->(
    name    => "file.mime.addtypes",
    levels  => [ qw(global host path) ],
    desc    => q{The directive modifies the MIME mappings by adding the specified MIME type mappings.},
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
    name    => "file.send-gzip",
    levels  => [ qw(global host path) ],
    default => q{file.send-gzip: OFF},
    desc    => <<'EOT',
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not so send <code>.gz</code> variants if possible.
EOT
)->(sub {
?>
<p>
If set to <code>ON</code>, the handler looks for a file with <code>.gz</code> appended and sends the file  (i.e. sends the contents of <code>index.html.gz</code> in place of <code>index.html</code>) if the client is capable of transparently decoding a gzipped response.
</p>
? })

? })
