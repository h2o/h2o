? my $ctx = $main::context;
? my ($content, $args) = @_;
<div id="<?= $args->{name} ?>" class="directive-head">
? if ($args->{since}) {
<div class="directive-since">since v<?= $args->{since} ?></div>
? }
<h3><a href="<?= $ctx->{filename} ?>#<?= $args->{name} ?>"><code>"<?= $args->{name} ?>"</code></a></h3>
</div>

<dl class="directive-desc">
<dt>Description:</dt>
<dd>
<p>
<?= Text::MicroTemplate::encoded_string($args->{desc}) ?>
</p>
<?= $content ?>
</dd>
<dt><a href="configure/syntax_and_structure.html#config_levels">Level</a>:</dt>
<dd><?= join(", ", @{$args->{levels}}) ?></dd>
? if ($args->{default}) {
<dt>Default:</dt>
<dd><code><pre><?= $args->{default} ?></pre></code>
? }
? if ($args->{see_also}) {
<dt>See also:</dt>
<dd><?= $args->{see_also} ?></dd>
? }
</dl>
