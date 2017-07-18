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

sub manformat {
    my ($content) = @_;
    my $ret = "";
    print(ref($content));
    my $parser = HTML::TokeParser::Simple->new( string => $content->as_string() );
    while (my $tok = $parser->get_token) {
        next unless $tok->is_text;
        $ret = $ret . $tok->as_is;
    }
    $ret;
};
?>
? if (@title) {
.SH <?= uc $title[-1] ?>
? }

?= manformat($content)

? if (my @notes = @{$ctx->{notes}}) {
.SS Notes:
.PP
? for (my $index = 0; $index < @notes; ++$index) {
[<?= $index + 1 ?>]<?= $notes[$index] ?>
? }
? }
