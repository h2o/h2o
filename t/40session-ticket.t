use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

my $tempdir = tempdir(CLEANUP => 1);

spawn_and_connect("file", "-sess_out $tempdir/session", "New");
spawn_and_connect("file", "-sess_in $tempdir/session -sess_out $tempdir/session", "Reused");
spawn_and_connect("file", "-sess_in $tempdir/session -sess_out $tempdir/session", "Reused");
spawn_and_connect("off", "-sess_in $tempdir/session -sess_out $tempdir/session", "New");

done_testing;

sub spawn_and_connect {
    my ($mode, $cmd_opts, $expected) = @_;
    my $server = spawn_h2o(<< "EOT");
ssl-session-resumption:
  mode: off
ssl-session-ticket:
  mode: $mode
  file: @{[ ASSETS_DIR ]}/session_tickets.yaml
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    my $lines = do {
        open my $fh, "-|", "openssl s_client $cmd_opts -connect 127.0.0.1:$server->{tls_port} 2>&1 < /dev/null"
            or die "failed to open pipe:$!";
        local $/;
        <$fh>;
    };
    $lines =~ m{---\n(New|Reused),}s
        or die "failed to parse the output of s_client:{{{$lines}}}";
    is $1, $expected;
}
