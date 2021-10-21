? my $ctx = $main::context;
? my ($content, $args) = @_;
.SS <?= $args->{name} ?>
? if ($args->{since}) {
(since v<?= $args->{since} ?>)
? }
<?= Text::MicroTemplate::encoded_string(decode_entities($args->{desc})) ?>

.PP
<?= $ctx->{unhtmlize}->(Text::MicroTemplate::encoded_string(decode_entities($content))) ?>
? if ($args->{see_also}) {
.PP
.BR See\ also:
<?= $args->{see_also} ?>
? }
.RE
.RE
