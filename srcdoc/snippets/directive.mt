? my $ctx = $main::context;
? my $args = shift;
<h3 id="<?= $args->{name} ?>" class="directive-title"><a href="<?= $ctx->{filename} ?>#<?= $args->{name} ?>"><code>"<?= $args->{name} ?>"</code></a></h3>

<dl>
<dt>Description:</dt>
<dd class="directive-desc"><?= Text::MicroTemplate::encoded_string($args->{desc}) ?></dd>
<dt><a href="configure/syntax_and_structure.html#config_levels">Level</a>:</dt>
<dd><?= join(", ", @{$args->{levels}}) ?></dd>
</dl>
