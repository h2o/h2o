? my $ctx = $main::context;
? my ($content, $args) = @_;
.SS <?= $args->{name} ?>
? if ($args->{since}) {
(since v<?= $args->{since} ?>)
? }
<?= Text::MicroTemplate::encoded_string($args->{desc}) ?>

.PP
<?= $content ?>
? if ($args->{see_also}) {
.PP
.BR See\ also:
<?= $args->{see_also} ?>
? }
.RE
.RE
