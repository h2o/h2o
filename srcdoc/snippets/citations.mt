? my $context = $main::context;
? my @notes = @_;
<ol class="citations">
? for (my $index = 0; $index < @notes; ++$index) {
<li><?= $notes[$index] ?></li>
? }
</ol>
