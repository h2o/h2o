<?
my $create_tab = sub {
   my ($fn, $title) = @_;
   my $html;
   if ($fn eq $main::context->{filename}) {
       $html = qq{<td class="selected">@{[Text::MicroTemplate::escape_html($title)]}</td>};
   } else {
       $html = qq{<td><a href="@{[Text::MicroTemplate::escape_html($fn)]}">@{[Text::MicroTemplate::escape_html($title)]}</a></td>};
   }
   Text::MicroTemplate::encoded_string($html);
};

?>
</head>
<body>
<div id="body">
<div id="top">
<h1><a href="./">H2O</a></h1>
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
<?= $create_tab->("./", "Top") ?>
<?= $create_tab->("install.html", "Install") ?>
<?= $create_tab->("configure.html", "Configure") ?>
<?= $create_tab->("libh2o.html", "Libh2o") ?>
<?= $create_tab->("faq.html", "FAQ") ?>
<td><a href="http://blog.kazuhooku.com/search/label/H2O" target="_blank">Blog</a></td>
<td><a href="http://github.com/h2o/h2o/" target="_blank">Source</a></td>
</tr>
</table>
