<div id="breadcrumb">
? for (my $i = 0; $i < @_; ++$i) {
?   if ($i != @_ - 1) {
<a href="<?= $_[$i]->[1] ?>"><?= $_[$i]->[0] ?></a> &gt;
?   } else {
<?= $_[$i]->[0] ?>
?   }
? }
</div>
