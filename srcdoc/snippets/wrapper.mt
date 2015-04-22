<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
? my $base = "../" x (scalar(split '/', $main::context->{filename}) - 1);
? if ($base ne '') {
<base href="<?= $base ?>" />
? }

<!-- oktavia -->
<link rel="stylesheet" href="assets/searchstyle.css" type="text/css" />
<script src="search/jquery-1.9.1.min.js"></script>
<script src="search/oktavia-jquery-ui.js"></script>
<script src="search/oktavia-english-search.js"></script>

<!-- /oktavia -->
<link rel="stylesheet" href="assets/style.css" type="text/css" />
?= $_[0]
<div id="footer">
<p>
Copyright &copy; 2015 <a href="http://dena.com/intl/">DeNA Co., Ltd.</a> et al.
</p>
</div>

</body>
</html>
