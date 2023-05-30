use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

# commands that are meant to exist without any documentation are listed here
my @private_commands = (
    qw(mruby.handler_path proxy.connect.proxy-status proxy.http2.max-concurrent_streams proxy-status.identity), # deprecated
    qw(header.cookie.unset header.cookie.unsetunless), # removing "cookie" headers in response?
    qw(http3-ack-frequency http3-allow-delayed-ack quic-nodes self-trace usdt-selective-tracing), # highly experimental and therefore undocumented
);

my $tempdir = tempdir(CLEANUP => 1);

# read commands from binary
system("@{[bindir]}/h2o --list-directives | sort > $tempdir/in_exec.txt") == 0
    or die "failed to extract list of commands supported by h2o executable:$?";

# read list of directives in the docs
open my $outfh, "|-", "sort > $tempdir/in_doc.txt"
    or die "failed to open pipe:$!";
print $outfh map { "$_\n" } @private_commands;
for my $fn (<doc/*.html doc/**/*.html>) {
    my $text = do {
        open my $fh, "<", $fn
            or die "failed to open file:$fn:$!";
        local $/;
        <$fh>;
    };
    #print "read $fn\n";
    while ($text =~ m{<div [^>]*class="directive-head"[^>]*>.*?<h3>.*?<code>"?(.*?)"?</code>.*?</h3>.*?</div>}sg) {
        print $outfh "$1\n";
    }
}
close $outfh;

# compare the commands
diag "If there is mismatch; add necessary documentation to files under srcdoc and run `make doc`.";
my $result = `cd $tempdir && exec diff -u in_exec.txt in_doc.txt`;
is $result, '', "all commands are documented";

done_testing();
