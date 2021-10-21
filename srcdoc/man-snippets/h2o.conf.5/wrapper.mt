<?

my ($content, @title) = @_;
my $ctx = $main::context;

?>
? if (@title) {
.SH <?= uc $title[-1] ?>
? }

?= $ctx->{unhtmlize}->($content)

? if (my @notes = @{$ctx->{notes}}) {
.SS Notes:
.PP
? for (my $index = 0; $index < @notes; ++$index) {
[<?= $index + 1 ?>]<?= $notes[$index] ?>
? }
? }
