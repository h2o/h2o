use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

# End-to-end tests of the webtransport.moq handler, and of the native MoQ listener (`moq` of `listen`), using moq-dev
# (https://github.com/moq-dev/moq) as the peers: `moq-relay` as the relay, and `moq` as the publisher and the subscriber.
for my $prog (qw(moq-relay moq ffmpeg)) {
    plan skip_all => "$prog not found"
        unless prog_exists($prog);
}

my $tempdir = tempdir(CLEANUP => 1);

# the video to be published, in Annex B
system("ffmpeg -loglevel error -f lavfi -i testsrc=size=320x240:rate=30 -t 3 -c:v libx264 -preset ultrafast -g 30 -bsf:v h264_mp4toannexb -f h264 $tempdir/in.h264") == 0
    or die "ffmpeg failed:$?";

# the relay
my $relay_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $relay = spawn_server(
    argv     => [ "sh", "-c", "exec moq-relay --listen 127.0.0.1:$relay_port --listen-tls-generate localhost --auth-public '**' > $tempdir/relay.log 2>&1" ],
    is_ready => sub { !Net::EmptyPort::can_bind("127.0.0.1", $relay_port, "udp") },
);

# h2o, accepting WebTransport on its HTTP/3 port and native MoQ on a QUIC listener of its own; moq-dev clients exit without waiting
# for their CONNECTION_CLOSE to be sent, leaving connections that the graceful shutdown closes only after the timeout
my $native_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $server = spawn_h2o({
    conf => << "EOT",
webtransport: ON
http3-graceful-shutdown-timeout: 1
hosts:
  default:
    listen:
      type: quic
      host: 127.0.0.1
      port: $native_port
      moq: moqt://127.0.0.1:$relay_port
      ssl:
        key-file: examples/h2o/server.key
        certificate-file: examples/h2o/server.crt
    paths:
      /moq:
        webtransport.moq:
          url: moqt://127.0.0.1:$relay_port
EOT
    extra_ports => { port => $native_port, proto => 'udp' },
});

my %urls = (
    h2o    => "https://127.0.0.1:$server->{quic_port}/moq",
    native => "moqt://127.0.0.1:$native_port",
    relay  => "moqt://127.0.0.1:$relay_port",
);

# Runs a subscriber, then a publisher, each connecting either through h2o or directly to the relay. As the subscriber starts first,
# it receives the entire video, which is published in real time. The subscriber is stopped before the broadcast ends, as moq-dev
# might end the subscriber's session before delivering the last group when the broadcast ends.
sub run_case {
    my ($name, $version, $pub_via, $sub_via) = @_;
    my $common = "--connect-version $version --connect-tls-insecure --connect-websocket-enabled=false --broadcast $name";

    my $sub_pid = fork;
    die "fork failed:$!"
        unless defined $sub_pid;
    if ($sub_pid == 0) {
        exec "exec moq --connect $urls{$sub_via} $common export h264 > $tempdir/$name.h264 2> $tempdir/$name-sub.log";
        die "failed to exec moq:$!";
    }
    sleep 1;

    # publish, keeping the input open after the video, until the subscriber is stopped
    my $pub_pid = fork;
    die "fork failed:$!"
        unless defined $pub_pid;
    if ($pub_pid == 0) {
        setpgrp(0, 0);
        exec "(ffmpeg -loglevel error -re -i $tempdir/in.h264 -c copy -f h264 -; touch $tempdir/$name-sent; sleep 30) | moq --connect $urls{$pub_via} $common import avc3 > $tempdir/$name-pub.log 2>&1";
        die "failed to exec sh:$!";
    }
    for (my $i = 0; $i < 100 && !-e "$tempdir/$name-sent"; ++$i) {
        sleep 0.1;
    }
    sleep 2;

    kill 'TERM', $sub_pid;
    waitpid($sub_pid, 0);
    kill 'TERM', -$pub_pid;
    waitpid($pub_pid, 0);
}

for my $version (qw(moq-transport-22 moq-transport-20)) {
    subtest $version => sub {
        my %cases = (
            direct          => [ qw(relay relay) ],
            "h2o-h2o"       => [ qw(h2o h2o) ],
            "h2o-relay"     => [ qw(h2o relay) ],
            "relay-h2o"     => [ qw(relay h2o) ],
            "native-native" => [ qw(native native) ],
            "native-relay"  => [ qw(native relay) ],
            "relay-native"  => [ qw(relay native) ],
            "h2o-native"    => [ qw(h2o native) ],
            "native-h2o"    => [ qw(native h2o) ],
        );
        # run the cases in parallel, each with a broadcast of its own
        my %pids;
        for my $case (sort keys %cases) {
            my $pid = fork;
            die "fork failed:$!"
                unless defined $pid;
            if ($pid == 0) {
                run_case("$version-$case", $version, @{$cases{$case}});
                POSIX::_exit(0);
            }
            $pids{$case} = $pid;
        }
        waitpid($_, 0) for values %pids;

        # Each subscriber receives the same bytes, though when the machine is busy, the last frames might be yet to be written when
        # it is stopped; hence every output is required to be a prefix of the longest, and not much shorter.
        my %outs = map {
            open my $fh, "<", "$tempdir/$version-$_.h264"
                or die "failed to open file:$!";
            local $/;
            ($_ => scalar <$fh>);
        } keys %cases;
        my ($longest) = sort { length $b <=> length $a } values %outs;
        cmp_ok length $longest, '>', 0, "received something";
        for my $case (sort keys %cases) {
            ok substr($longest, 0, length $outs{$case}) eq $outs{$case} && length $outs{$case} >= length($longest) / 2,
                "publisher-subscriber: $case"
                or diag "received @{[length $outs{$case}]} of @{[length $longest]} bytes\n",
                    `cat $tempdir/$version-$case-sub.log $tempdir/$version-$case-pub.log`;
        }
    };
}

done_testing;
