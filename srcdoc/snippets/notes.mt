? my $ctx = $main::context;
? my @notes = @{$ctx->{notes}};
? if (@notes) {
<div class="notes">
<h3>Notes:</h3>
<ol>
? for (my $index = 0; $index < @notes; ++$index) {
<li id="note_<?= $index + 1 ?>"><?= $notes[$index] ?></li>
? }
</ol>
</div>
? }
