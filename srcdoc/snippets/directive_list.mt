? my $ctx = $main::context;
? my ($content, $args) = @_;
<ul>
? for my $directive (@{ $args->{directives} }) {
<li><a href="<?= $args->{path} ?>#<?= $directive ?>">
<code><?= $directive ?></code>
</a></li>
? }
</ul>

?= $_[0]
