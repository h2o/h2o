<?

my ($content, @title) = @_;
my $ctx = $main::context;
my $create_tab = sub {
    my ($fn, $tab_topic) = @_;
    my $html;
    my $cur_topic = $title[0] || 'Top';
    $cur_topic = "FAQ"
        if $cur_topic eq 'Frequently Asked Questions';
    if ($cur_topic eq $tab_topic) {
        $html = qq{<td class="selected">@{[Text::MicroTemplate::escape_html($tab_topic)]}</td>};
    } else {
        $html = qq{<td><a href="@{[Text::MicroTemplate::escape_html($fn)]}">@{[Text::MicroTemplate::escape_html($tab_topic)]}</a></td>};
    }
    Text::MicroTemplate::encoded_string($html);
};

?><!DOCTYPE html>
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

<title><?= join " - ", ($ctx->{filename} ne 'index.html' ? reverse @title : ()), "H2O" ?></title>
</head>
<body>
<div id="body">
<div id="top">

<h1><a href="index.html">H2O</a></h1>
the optimized HTTP/1.x, HTTP/2 server

<!-- oktavia -->
<form id="searchform">
<input class="search" type="search" name="search" id="search" results="5" value="" placeholder="Search" />
<div id="searchresult_box">
<div id="close_search_box">&times;</div>
<div id="searchresult_summary"></div>
<div id="searchresult"></div>
<div id="searchresult_nav"></div>
<span class="pr">Powered by <a href="https://github.com/shibukawa/oktavia">Oktavia</a></span>
</div>
</form>
<!-- /oktavia -->

</div>

<table id="menu">
<tr>
<?= $create_tab->("index.html", "Top") ?>
<?= $create_tab->("install.html", "Install") ?>
<?= $create_tab->("configure.html", "Configure") ?>
<?= $create_tab->("faq.html", "FAQ") ?>
<td><a href="http://blog.kazuhooku.com/search/label/H2O" target="_blank">Blog</a></td>
<td><a href="http://github.com/h2o/h2o/" target="_blank">Source</a></td>
</tr>
</table>

<div id="main">

? if (@title) {
<h2>
?     if (@title > 1) {
?         for (my $i = 0; $i < @title - 1; $i++) {
<a href="<?= lc $title[$i] ?>.html"><?= $title[$i] ?></a> &gt;
?         }
?     }
<?= $title[-1] ?>
</h2>
? }

?= $content

? if (my @notes = @{$ctx->{notes}}) {
<div class="notes">
<h3>Notes:</h3>
<ol>
? for (my $index = 0; $index < @notes; ++$index) {
<li id="note_<?= $index + 1 ?>"><?= $notes[$index] ?></li>
? }
</ol>
</div>
? }

</div>
<div id="footer">
<p>
Copyright &copy; 2015 <a href="http://dena.com/intl/">DeNA Co., Ltd.</a> et al.
</p>
</div>
</body>
</html>
