use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");
#plan skip_all => "openssl 1.0.2 or above is required"
#    unless `openssl version` =~ /^OpenSSL 1\.(?:0\.[2-9][^0-9]|[1-9])/s;

my $tempdir = tempdir(CLEANUP => 1);

subtest "internal" => sub {
    spawn_with(<< "EOT",
  mode: ticket
EOT
    sub {
        sleep 1;
        is test("new"), "New";
        is test("reuse"), "Reused";
        is test("reuse"), "Reused";
    });
    spawn_with(<< "EOT",
  mode: ticket
EOT
    sub {
        is test("reuse"), "New";
    });
};

subtest "file" => sub {
    my $tickets_file = "t/40session-ticket/forever_ticket.yaml";
    spawn_with(<< "EOT",
  mode: ticket
  ticket-store: file
  ticket-file: $tickets_file
num-threads: 1
EOT
    sub {
        sleep 1; # wait for tickets file to be loaded
        is test("new"), "New";
        is test("reuse"), "Reused";
        is test("reuse"), "Reused";
    });
    spawn_with(<< "EOT",
  mode: ticket
  ticket-store: file
  ticket-file: $tickets_file
EOT
    sub {
        sleep 1; # wait for tickets file to be loaded
        is test("reuse"), "Reused";
    });
};

subtest "no-tickets-in-file" => sub {
    my $tickets_file = "t/40session-ticket/nonexistent";
    spawn_with(<< "EOT",
  mode: ticket
  ticket-store: file
  ticket-file: $tickets_file
num-threads: 1
EOT
    sub {
        sleep 1; # wait for tickets file to be loaded
        is test("new"), "New";
        is test("reuse"), "New";
        is test("reuse"), "New";
    });
};

subtest "memcached" => sub {
    plan skip_all => "memcached not found"
        unless prog_exists("memcached");
    my $memc_port = empty_port();
    my $doit = sub {
        my $memc_proto = shift;
        my $memc_guard = spawn_server(
            argv     => [ qw(memcached -l 127.0.0.1 -p), $memc_port, "-B", $memc_proto ],
            is_ready => sub {
                check_port($memc_port);
            },
        );
        my $conf =<< "EOT";
  mode: ticket
  ticket-store: memcached
  memcached:
    host: 127.0.0.1
    port: $memc_port
    protocol: $memc_proto
num-threads: 1
EOT
        spawn_with($conf, sub {
            sleep 1;
            is test("new"), "New";
            is test("reuse"), "Reused";
            is test("reuse"), "Reused";
        });
        spawn_with($conf, sub {
            sleep 1;
            is test("reuse"), "Reused";
        });
    };
    $doit->("binary");
    $doit->("ascii");
};

done_testing;

my $server;

sub spawn_with {
    my ($opts, $cb) = @_;
    $server = spawn_h2o(<< "EOT");
ssl-session-resumption:
$opts
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    $cb->();
}

sub test {
    my $sess_mode = shift @_; # reuse or new

    # 'openssl -sess_out' writes a session file ONLY if
    #     a session was handed out by the server!

    my $cmd_opts;
    if ( $sess_mode eq 'new' ) {
        unlink "$tempdir/session";
        $cmd_opts = "-sess_out $tempdir/session";
    } else {
        return "no session to reuse $tempdir/session does no exist" unless ( -e "$tempdir/session" );
        $cmd_opts = "-sess_in $tempdir/session";
    }

    my $lines = do {
        open my $fh, "-|", "timeout 1 openssl s_client $cmd_opts -connect 127.0.0.1:$server->{tls_port} 2>&1"
            or die "failed to open pipe:$!";
        local $/;
        <$fh>;
    };
    $lines =~ m{---\n(New|Reused),}s
        or die "failed to parse the output of s_client:{{{$lines}}}";

    if ( $sess_mode eq 'new' ) {
        -e "$tempdir/session" ? $1 :  "no session created $tempdir/session does no exist";
    } else {
        $1;
    }
}
