use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");
#plan skip_all => "openssl 1.0.2 or above is required"
#    unless `openssl version` =~ /^OpenSSL 1\.(?:0\.[2-9][^0-9]|[1-9])/s;

my $tempdir = tempdir(CLEANUP => 1);

subtest "internal" => sub {
    spawn_with("ticket", "internal", "unused", sub {
        is test(), "New";
        test(); # openssl 0.9.8 seems to return "New" (maybe because in the first run we did not specify -sess_in)
        is test(), "Reused";
        is test(), "Reused";
    });
    spawn_with("ticket", "internal", "unused", sub {
        is test(), "New";
    });
};

subtest "file" => sub {
    my $tickets_file = "t/40session-ticket/forever_ticket.yaml";
    spawn_with("ticket", "file", $tickets_file, sub {
        is test(), "New";
        is test(), "Reused";
        is test(), "Reused";
    });
    spawn_with("ticket", "file", $tickets_file, sub {
        is test(), "Reused";
    });
};

subtest "no-tickets-in-file" => sub {
    my $tickets_file = "t/40session-ticket/nonexistent";
    spawn_with("ticket", "file", $tickets_file, sub {
        is test(), "New";
        is test(), "New";
        is test(), "New";
    });
};

done_testing;

my $server;

sub spawn_with {
    my ($mode, $store, $tickets_file, $cb) = @_;
    $server = spawn_h2o(<< "EOT");
ssl-session-resumption:
  mode: $mode
  ticket-store: $store
  file: $tickets_file
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    $cb->();
}

sub test {
    my $lines = do {
        my $cmd_opts = (-e "$tempdir/session" ? "-sess_in $tempdir/session" : "") . " -sess_out $tempdir/session";
        open my $fh, "-|", "openssl s_client $cmd_opts -connect 127.0.0.1:$server->{tls_port} 2>&1 < /dev/null"
            or die "failed to open pipe:$!";
        local $/;
        <$fh>;
    };
    $lines =~ m{---\n(New|Reused),}s
        or die "failed to parse the output of s_client:{{{$lines}}}";
    $1;
}
