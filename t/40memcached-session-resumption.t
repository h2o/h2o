use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => "could not find memcached"
    unless prog_exists("memcached");

plan skip_all => "could not find openssl"
    unless prog_exists("openssl");

my $tempdir = tempdir(CLEANUP => 1);

doit("binary");
doit("ascii");

done_testing;

sub doit {
    my $memc_proto = shift;
    subtest $memc_proto => sub {
        # start memcached
        my $memc_port = empty_port();
        my $memc_guard = spawn_server(
            argv     => [ qw(memcached -l 127.0.0.1 -p), $memc_port, "-B", $memc_proto ],
            is_ready => sub {
                check_port($memc_port);
            },
        );
        # the test
        my $spawn_and_connect = sub {
            my ($opts, $expected) = @_;
            my $server = spawn_h2o(<< "EOT");
ssl-session-resumption:
  mode: cache
  cache-store: memcached
  memcached:
    host: 127.0.0.1
    port: $memc_port
    protocol: $memc_proto
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
            my $lines = do {
                open my $fh, "-|", "openssl s_client -no_ticket $opts -connect 127.0.0.1:$server->{tls_port} 2>&1 < /dev/null"
                    or die "failed to open pipe:$!";
                local $/;
                <$fh>;
            };
            $lines =~ m{---\n(New|Reused),}s
                or die "failed to parse the output of s_client:{{{$lines}}}";
            is $1, $expected;
        };
        $spawn_and_connect->("-sess_out $tempdir/session", "New");
        $spawn_and_connect->("-sess_in $tempdir/session", "Reused");
    };
}
