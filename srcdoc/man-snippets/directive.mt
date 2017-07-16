? my $ctx = $main::context;
? my ($content, $args) = @_;
.SH <?= $args->{name} ?>
<?= $args->{desc} ?>
.PP
.RS
<?= $args->{name} ?>
? if ($args->{since}) {
since v<?= $args->{since} ?>
? }

.PP
Description:
.PP
.RS
<?= Text::MicroTemplate::encoded_string($args->{desc}) ?>
<?= $content ?>
? if ($args->{see_also}) {
.PP
.BR See also:
<?= $args->{see_also} ?>
? }
.RE
.RE
