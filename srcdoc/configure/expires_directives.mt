? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Expires Directives")->(sub {

<p>
This document describes the configuration directives of the expires handler.
</p>

<?
$ctx->{directive}->(
    name    => "expires",
    levels  => [ qw(global host path extension) ],
    desc    => <<'EOT',
An optional directive for setting the <code>Cache-Control: max-age=</code> header.
EOT
)->(sub {
?>
<ul>
<li>if the argument is <code>OFF</code> the feature is not used
<li>if the value is <code><i>NUMBER</i> <i>UNIT</i></code> then the header is set
<li>the units recognized are: <code>second</code>, <code>minute</code>, <code>hour</code>, <code>day</code>, <code>month</code>, <code>year</code>
<li> the units can also be in plural forms
</ul>
<?= $ctx->{example}->('Set <code>Cache-Control: max-age=86400</code>', <<'EOT')
expires: 1 day
EOT
?>
<p>
You can also find an example that conditionally sets the header depending on the aspects of a request in <a href="configure/mruby.html#modifying-response">Modifying the Response section of the Mruby directives documentation</a>.
</p>
? })

? })
