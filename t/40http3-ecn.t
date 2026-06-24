use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use Net::EmptyPort qw(wait_port);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

sub run_case {
    my ($server_ecn, $client_ecn) = @_;

    my $tempdir = tempdir(CLEANUP => 1);

    my $quic_port = empty_port({
        host  => "0.0.0.0",
        proto => "udp",
    });

    my $conf = << "EOT";
access-log:
  format: "%{http3.quic-stats}x"
  path: "$tempdir/access_log"
listen:
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  quic:
    ecn: $server_ecn
hosts:
  default:
    paths:
      /asset:
        file.dir: doc
EOT

    my $server = spawn_h2o($conf);
    wait_port({port => $quic_port, proto => "udp"});

    my @client_opts = ($client_prog, "-3", "100", "-k");
    push @client_opts, "--no-http3-ecn"
        if $client_ecn eq "OFF";
    push @client_opts, "https://127.0.0.1:$quic_port/asset/assets/8mbps100msec-nginx195-h2o150.png";

    my $resp = join("", `@client_opts 2>&1`);
    like $resp, qr{^HTTP/3 200\b}ms, "http/3 is ok";

    sleep 0.1;

    open my $logfh, "<", "$tempdir/access_log"
        or die "failed to open $tempdir/access_log:$!";
    my @lines = <$logfh>;
    is scalar(@lines), 1, "one access log line";

    # The access log exposes the server-side QUIC stats. We use it to check both
    # directions:
    #  - received-ecn-* tells us what the client sent to the server
    #  - num-paths.ecn-validated tells us if the server's own ECN-marked packets
    #    were acknowledged using ACK_ECN
    if ($client_ecn eq "ON") {
        like $lines[0], qr{(?:^|,)num-packets\.received-ecn-ect0=[1-9][0-9]*(?:,|$)}, "client sent ECN-marked packets";
    } else {
        unlike $lines[0], qr{(?:^|,)num-packets\.received-ecn-ect0=[1-9][0-9]*(?:,|$)}, "client did not send ECN-marked packets";
    }

    if ($server_ecn eq "ON") {
        like $lines[0], qr{(?:^|,)num-paths\.ecn-validated=[1-9][0-9]*(?:,|$)}, "ecn validation succeeded";
    } else {
        unlike $lines[0], qr{(?:^|,)num-paths\.ecn-validated=[1-9][0-9]*(?:,|$)}, "ecn validation did not succeed";
    }

    undef $server;
}

for my $server_ecn (qw(ON OFF)) {
    for my $client_ecn (qw(ON OFF)) {
        subtest "server=$server_ecn client=$client_ecn" => sub {
            run_case($server_ecn, $client_ecn);
        };
    }
}

done_testing;
