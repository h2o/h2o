? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Headers Directives")->(sub {

<p>
This document describes the configuration directives of the headers handler.
</p>

<?= $_mt->render_file("directive.mt", {
    name    => "header.add",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Adds a new header line to the response headers, regardless if a header with the same name already exists.
</p>
<div class="example">
<div class="caption">Example. Setting the <code>Set-Cookie</code> header</div>
<pre><code>header.add: "Set-Cookie: test=1"</code></pre>
</div>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name    => "header.append",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
Adds a new header line, or appends the value to the existing header with the same name, separated by <code>,</code>.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name => "header.merge",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Adds a new header line, or merges the value to the existing header of comma-separated values.
</p>
<p>
The following example sets the <code>must-revalidate</code> attribute of the <code>Cache-Control</code> header when and only when the attribute is not yet being set.
</p>
<div class="example">
<div class="caption">Example. Setting the <code>must-revalidate</code> attribute</div>
<pre><code>header.merge: "Cache-Control: must-revalidate"</code></pre>
</div>
EOT
}) ?>


<?= $_mt->render_file("directive.mt", {
    name => "header.set",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Sets a header line, removing headers with the same name if exists.
</p>
<div class="example">
<div class="caption">Example. Setting the <code>X-Content-Type-Options: nosniff</code> header</div>
<pre><code>header.append: "X-Content-Type-Options: nosniff"</code></pre>
</div>
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name => "header.setifempty",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
Sets a header line when and only when a header with the same name does not already exist.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name => "header.setifempty",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
Sets a header line when and only when a header with the same name does not already exist.
EOT
}) ?>

<?= $_mt->render_file("directive.mt", {
    name => "header.unset",
    levels  => [ qw(global host path) ],
    desc    => <<'EOT',
<p>
Removes headers with given name.
</p>
<div class="example">
<div class="caption">Example. Removing the <code>X-Powered-By</code> header</div>
<pre><code>header.unset: "X-Powered-By"</code></pre>
</div>
EOT
}) ?>

? })
