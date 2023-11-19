use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use POSIX qw(WNOHANG);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $halfdome_jpg_size = (stat "t/assets/doc_root/halfdome.jpg")[7];

subtest "successful-migration" => sub {
    my $doit = sub {
        my ($multipath_onoff) = shift;

        # spawn server
        my $server = spawn_h2o(build_conf(<< "EOT"));
    multipath: $multipath_onoff
EOT

        my $run_client_and_check = sub {
            my $opts = shift;
            my %quic_stats = run_client_get_quic_stats($quic_port, 'USR1', $opts);
            isnt scalar(keys %quic_stats), 0, "requests succeeded";
            is(
                $quic_stats{"paths-migration-elicited"},
                ($multipath_onoff eq 'on' && (grep { /--multipath/ } @$opts) ? 0 : 1),
                "path migration elicited",
            );
            is $quic_stats{"paths-promoted"}, 1, "path promoted";
            is $quic_stats{"paths-validated"}, 1, "path validated";
            is $quic_stats{"paths-validation-failed"}, 0, "path validation failed";
            cmp_ok $quic_stats{"packets-sent-promoted-paths"}, ">", $halfdome_jpg_size / 1500, "2nd response sent using promoted path";
        };

        subtest "client-multipath:off" => sub {
            $run_client_and_check->([]);
        };
        subtest "client-multipath:on" => sub {
            $run_client_and_check->([ qw(--multipath) ]);
        };
    };

    subtest "server-multipath:off" => sub {
        $doit->("off");
    };

    subtest "server-multipath:on" => sub {
        $doit->("on");
    };
};

subtest "disable-migration" => sub {
    my $server = spawn_h2o(build_conf(<< "EOT"));
    max-path-validation-failures: 0
EOT

    my %quic_stats = run_client_get_quic_stats($quic_port, 'USR1', []);
    is scalar(keys %quic_stats), 0, "request after NAT rebinding does not complete";
};

subtest "multipath" => sub {
    my $udpfw_prog = bindir() . "/quicly/udpfw";
    plan skip_all => "$udpfw_prog not found"
        unless -e $udpfw_prog;
    my $udpfw_port = empty_port({
        host  => "127.0.0.1",
        proto => "udp",
    });

    # spawn forwarder
    my $udpfw_guard = do {
        my $pid = fork;
            die "fork failed:$!"
        unless defined $pid;
        if ($pid == 0) {
            open STDERR, ">", "/dev/null"
                or die "failed to redirect STDERR to /dev/null:$!";
            exec $udpfw_prog, qw(-I 1000 -l), $udpfw_port, "127.0.0.1", $quic_port;
            die "failed to spawn $udpfw_prog:$!";
        }
        make_guard(sub {
            kill 'KILL', $pid;
            while (waitpid($pid, 0) != $pid) {}
        });
    };

    my $server = spawn_h2o(build_conf(<< "EOT"));
    multipath: ON
EOT

    my %quic_stats = run_client_get_quic_stats($udpfw_port, 'USR2', [ qw(--multipath) ]);
    isnt scalar(keys %quic_stats), 0, "requests suceeded";
    is $quic_stats{"paths-migration-elicited"}, 0, "no path migration";
    cmp_ok $quic_stats{"packets-sent-promoted-paths"}, '>=', 10, "packets sent on alternative path";
    cmp_ok $quic_stats{"packets-ack-received-promoted-paths"}, '>=', 10, "packets on alternative path acked";
};

done_testing;

sub build_conf {
    my $quic_opts = shift;
    return << "EOT";
listen:
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  quic:
$quic_opts
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
access-log:
  format: "\%r \%s \%b \%{http3.quic-stats}x"
  path: $tempdir/access_log
EOT
}

sub run_client_get_quic_stats {
    my ($port, $sig, $extra_opts) = @_;

    # launch client that fetches twice with 1 second delay
    my $client_pid = fork;
    die "fork failed:$!"
    unless defined $client_pid;
    if ($client_pid == 0) {
        open STDOUT, ">", "$tempdir/client_log"
            or die "failed to open /dev/null:$!";
        open STDERR, ">&STDOUT"
            or die "failed to redirect STDERR to STDOUT:$!";
        exec $client_prog, qw(-3 100 -d 1000 -t 2), @$extra_opts, "https://127.0.0.1:$port/halfdome.jpg";
        die "exec failed:$!";
    }

    # induce path migration after 0.5 seconds, wait for client to exit
    sleep 0.5;
    kill $sig, $client_pid;
    for (my $i = 0; waitpid($client_pid, WNOHANG) != $client_pid; ++$i) {
        if ($i > 30) {
            # waited for 3 seconds but failed, return empty hash
            kill 'KILL', $client_pid;
            while (waitpid($client_pid, 0) != $client_pid) {}
            return;
        }
        sleep 0.1;
    }

    sleep 0.5; # wait for the log to be emitted

    # read the logs
    my $loglines = do {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open access log:$!";
        local $/;
        <$fh>;
    };
    debug("log:\n$loglines");

    $loglines =~ /([^\n]*)\n$/s
        or die "failed to extract last log line";
    my $last_log = $1;

    like $last_log, qr{^GET /halfdome\.jpg HTTP/3 200 $halfdome_jpg_size }, "request success";
    parse_quic_stats((split " ", $last_log)[5]);
}

sub parse_quic_stats {
    my $line = shift;
    my %quic_stats;
    for (split /,/, $line) {
        my ($n, $v) = split /=/, $_, 2;
        $quic_stats{$n} = $v;
    }
    %quic_stats;
}
