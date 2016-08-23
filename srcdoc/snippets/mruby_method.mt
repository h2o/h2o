? my $ctx = $main::context;
? my ($content, $args) = @_;
<div id="<?= $args->{name} ?>" class="mruby-method-head">
? if ($args->{since}) {
<div class="mruby-method-since">since v<?= $args->{since} ?></div>
? }
<h3><a href="<?= $ctx->{filename} ?>#<?= $args->{name} ?>"><code>"<?= $args->{name} ?>"</code></a></h3>
</div>

<dl class="mruby-method-desc">
<dt>Description:</dt>
<dd>
<p>
<?= Text::MicroTemplate::encoded_string($args->{desc}) ?>
</p>
<?= $content ?>
</dd>
? if (@{$args->{params} || []}) {
<dt>Parameters:</dt>
<dd>
<dl class="mruby-method-parameters">
? for my $param (@{ $args->{params} }) {
  <dt><?= $param->{label} ?></dt>
  <dd><?= $param->{desc} ?></dd>
? }
</dl>
</dd>
? }
? if ($args->{see_also}) {
<dt>See also:</dt>
<dd><?= $args->{see_also} ?></dd>
? }
</dl>
