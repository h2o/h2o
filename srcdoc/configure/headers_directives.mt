? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Headers Directives")->(sub {

<p>
Headers directives can be used to manipulate response headers.
This document describes the configuration directives of the headers handler.
</p>

<p>
Starting from v2.3, it is possible to specify the timing when the headers directives is applied. All of the header directives can take either of the following two forms.
</p>

<?= $ctx->{example}->('Scalar Form', <<'EOT');
header.add: "X-Foo: FOO":
EOT
?>

<?= $ctx->{example}->('Mapping Form', <<'EOT');
header.add:
  header: "X-Foo: FOO":
  when: final
EOT
?>

<p>
The above two are identical. <code>when</code> can be eigher of: <code>final</code>, <code>early</code>, <code>all</code>, and default is <code>final</code>. If the value is <code>final</code>, the header directive is only applied to final (not 1xx) response. If the value is <code>early</code>, it's only applied to 1xx informational responses. If <code>all</code> is set, it's applied to both of final and 1xx responses.
</p>

? $ctx->{directive_list}->()->(sub {

<?
$ctx->{directive}->(
    name    => "header.add",
    levels  => [ qw(global host path extension) ],
    desc    => q{Adds a new header line to the response headers, regardless if a header with the same name already exists.},
)->(sub {
?>
<div class="example">
<div class="caption">Example. Setting the <code>Set-Cookie</code> header</div>
<pre><code>header.add: "Set-Cookie: test=1"</code></pre>
</div>
? })

<?
$ctx->{directive}->(
    name    => "header.append",
    levels  => [ qw(global host path extension) ],
    desc    => <<'EOT',
Adds a new header line, or appends the value to the existing header with the same name, separated by <code>,</code>.
EOT
)->(sub {});
?>

<?
$ctx->{directive}->(
    name => "header.merge",
    levels  => [ qw(global host path extension) ],
    desc    => <<'EOT',
Adds a new header line, or merges the value to the existing header of comma-separated values.
EOT
)->(sub {
?>
<p>
The following example sets the <code>must-revalidate</code> attribute of the <code>Cache-Control</code> header when and only when the attribute is not yet being set.
</p>
<?= $ctx->{example}->('Setting the <code>must-revalidate</code> attribute', <<'EOT')
header.merge: "Cache-Control: must-revalidate"
EOT
?>
? })

<?
$ctx->{directive}->(
    name => "header.set",
    levels  => [ qw(global host path extension) ],
    desc    => q{Sets a header line, removing headers with the same name if exists.},
)->(sub {
?>
<?= $ctx->{example}->('Setting the <code>X-Content-Type-Options: nosniff</code> header', <<'EOT')
header.set: "X-Content-Type-Options: nosniff"
EOT
?>
? })

<?
$ctx->{directive}->(
    name => "header.setifempty",
    levels  => [ qw(global host path extension) ],
    desc    => <<'EOT',
Sets a header line when and only when a header with the same name does not already exist.
EOT
)->(sub {});

<?
$ctx->{directive}->(
    name => "header.unset",
    levels  => [ qw(global host path extension) ],
    desc    => q{Removes headers with given name.},
)->(sub {
?>
<?= $ctx->{example}->('Removing the <code>X-Powered-By</code> header', <<'EOT')
header.unset: "X-Powered-By"
EOT
?>
? })

? })

? })
