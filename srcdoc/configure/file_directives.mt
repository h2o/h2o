? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "File Directives")->(sub {

<p>
This document describes the configuration directives of the file handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "file.dir",
    levels  => [ qw(path) ],
    desc    => <<'EOT',
<p>
The directive specifies the directory under which should be served for the corresponding path.
</p>
<div class="example">
<div class="caption">Example. Serving files under different paths</div>
<pre><code>paths:
    "/":
        file.dir: /path/to/doc-root
    "/icons":
        file.dir: /path/to/icons-dir
</code></pre>
</div>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.dirlisting",
    levels  => [ qw(global host path) ],
    default => 'file.dirlisting: OFF',
    desc    => <<'EOT',
A boolean flag (<code>OFF</code>, or <code>ON</code>) specifying whether or not to send the directory listing in case none of the index files (as specified by the <a href="configure/file_directives.html#file.index"><code>file.index</code></a> directive) exists.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.etag",
    levels  => [ qw(global host path) ],
    default => 'file.etag: ON',
    desc    => <<'EOT',
A boolean flag (<code>OFF</code>, or <code>ON</code>) specifying whether or not to send etags.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.index",
    levels  => [ qw(global host path) ],
    default => "file.etag: [ 'index.html', 'index.htm', 'index.txt' ]",
    desc    => <<'EOT',
<p>
Specifies the names of the files that should be served when the client sends a request against the directory.
</p>
<p>
The sequence of filenames afer search from left to right, and the first file that existed is sent to the client.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.mime.addtypes",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
The directive modifies the MIME mappings by adding the specified MIME type mappings.
</p>
<div class="example">
<div class="caption">Example. Adding MIME mappings</div>
<pre><code>file.mime.addtypes:
    "application/javascript": ".js"
    "image/jpeg": [ ".jpg", ".jpeg" ]
</code></pre>
</div>
<p>
The default mappings is hard-coded in <a href="https://github.com/h2o/h2o/blob/master/lib/handler/mimemap/defaults.c.h">lib/handler/mimemap/defaults.c.h</a>.
</p>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.mime.removetypes",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Removes the MIME mappings for specified extensions supplied as a sequence of extensions.
</p>
<div clas="example">
<div class="caption">Example. Remove MIME mappings</div>
<pre><code>file.mime.removetypes: [ ".jpg", ".jpeg" ]</code></pre>
</div>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.mime.setdefaulttype",
    levels  => [ qw(global host path) ],
    default => q{file.mime.setdefaulttype: "application/octet-stream"},
    desc    => <<'EOT',
Sets the default MIME-type that is used when an extension does not exist in the MIME mappings.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "file.mime.settypes",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Resets the MIME mappings to given mapping.
</p>
<div class="example">
<div class="caption">Example. Resets the MIME mappings to minimum</div>
<pre><code>file.mime.settypes:
    "text/html":  [ ".html", ".htm" ]
    "text/plain": ".txt"
</code></pre>
</div>
EOT
}) ?>


<?= $_mt->render_file("directive.mt", {
    name    => "file.send-gzip",
    levels  => [ qw(global host path) ],
    default => q{file.send-gzip: OFF},
    desc    => <<'EOT',
<p>
A boolean flag (<code>ON</code> or <code>OFF</code>) indicating whether or not so send <code>.gz</code> variants if possible.
</p>
<p>
If set to <code>ON</code>, the handler looks for a file with <code>.gz</code> appended and sends the file  (i.e. sends the contents of <code>index.html.gz</code> in place of <code>index.html</code>) if the client is capable of transparently decoding a gzipped response.
</p>
EOT
}) ?>

? })
