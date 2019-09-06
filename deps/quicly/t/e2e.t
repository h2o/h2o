#! /usr/bin/env perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use JSON;
use Net::EmptyPort qw(empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);

plan skip_all => 'WITH_DTRACE not set to ON, skipping'
    unless $ENV{WITH_DTRACE} =~ /^on$/i;
plan skip_all => 'test does not support linux (yet)'
    if $^O eq 'linux';

sub complex ($$;$) {
    my $s = shift;
    my $cb = shift;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    local $_ = $s;
    if ($cb->()) {
        &pass;
    } else {
        &fail;
        diag($s);
    }
}

$ENV{BINARY_DIR} ||= ".";
my $cli = "$ENV{BINARY_DIR}/cli";
my $port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $tempdir = tempdir(CLEANUP => 1);

system("misc/probe2trace.pl < quicly-probes.d > $tempdir/dtrace.d") == 0 && $? == 0
    or die "failed to generate dtrace script:$?";

subtest "hello" => sub {
    my $guard = spawn_server();
    my $resp = `@{[build_trace_cmd(cmd => "$cli -p /12.txt 127.0.0.1 $port")]} 2> /dev/null`;
    is $resp, "hello world\n";
    subtest "events" => sub {
        my $events = read_events();
        complex $events, sub {
            $_ =~ /"type":"transport-close-send",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)"/s
                and $1 eq 'packet-commit' and $2 eq 'quictrace-sent' and $3 eq 'send' and $4 eq 'free';
        };
    };
};

subtest "version-negotiation" => sub {
    my $guard = spawn_server();
    my $resp = `@{[build_trace_cmd(cmd => "$cli -n -p /12.txt 127.0.0.1 $port")]} 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = read_events();
    if ($events =~ /"type":"connect",.*"version":(\d+)(?:.|\n)*"type":"version-switch",.*"new-version":(\d+)/m) {
        is $2, 0xff000016;
        isnt $1, 0xff000016;
    } else {
        fail "no quic-version-switch event";
        diag $events;
    }
};

subtest "retry" => sub {
    my $guard = spawn_server(opts => [qw(-R)]);
    my $resp = `@{[build_trace_cmd(cmd => "$cli -p /12.txt 127.0.0.1 $port")]} 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = read_events();
    complex $events, sub {
        $_ =~ qr/"type":"receive",.*"first-octet":(\d+).*\n.*"type":"stream-lost",.*"stream-id":-1,.*"off":0,/ and $1 >= 240
    }, "CH deemed lost in response to retry";
};

unlink "$tempdir/session";

subtest "0-rtt" => sub {
    my $guard = spawn_server();
    my $resp = `@{[build_trace_cmd(cmd => "$cli -s $tempdir/session -p /12.txt 127.0.0.1 $port")]} 2> /dev/null`;
    is $resp, "hello world\n";
    ok -e "$tempdir/session", "session saved";
    system build_trace_cmd(cmd => "$cli -s $tempdir/session 127.0.0.1 $port") . '> /dev/null 2>&1';
    my $events = read_events();
    like $events, qr/"type":"stream-send".*"stream-id":0,(.|\n)*"type":"packet-commit".*"pn":1,/m, "stream 0 on pn 1";
    like $events, qr/"type":"cc-ack-received".*"largest-acked":1,/m, "pn 1 acked";
};

subtest "stateless-reset" => sub {
    my $guard = spawn_server(opts => [qw(-C deadbeef)]);
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # child process
        open STDOUT, '>', '/dev/null'
            or die "failed to redirect stdout to /dev/null:$!";
        exec 'sh', '-c', build_trace_cmd(cmd => "$cli -i 5000 127.0.0.1 $port");
        die "failed to exec $cli:$!";
    }
    # parent process, let the client fetch the first response, then kill respawn the server using same CID encryption key
    sleep 4;
    undef $guard;
    $guard = spawn_server(opts => [qw(-C deadbeef)]);
    # wait for the child to die
    while (waitpid($pid, 0) != $pid) {
    }
    # check that the stateless reset is logged
    my $events = read_events();
    like $events, qr/"type":"stateless-reset-receive",/m;
};

subtest "idle-timeout" => sub {
    my $guard = spawn_server(opts => [qw(-I 1000)], trace => {events => "$tempdir/server-events"});
    my $resp = `@{[build_trace_cmd(cmd => "$cli -p /12.txt -i 2000 127.0.0.1 $port", events => "$tempdir/client-events")]} 2> /dev/null`;
    # Because we start using idle timeout at the moment we dispose handshake key (currently 3PTO after handshake), there is an
    # uncertainty in if the first request-response is covered by the idle timeout.  Therefore, we check if we have either one or
    # to responses, add a sleep in case server timeouts after client does, pass the case where the server sends stateless-reset...
    like $resp, qr/^hello world\n(|hello world\n|)$/s;
    sleep 2;
    undef $guard;
    like slurp_file("$tempdir/client-events"), qr/"type":("idle-timeout"|"stateless-reset-receive"),/m;
    like slurp_file("$tempdir/server-events"), qr/"type":"idle-timeout",/m;
};

subtest "blocked-streams" => sub {
    my $guard = spawn_server(opts => [qw(-X 2)]);
    my $resp = `$cli -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\n";
    $resp = `$cli -p /12.txt -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\n";
    $resp = `$cli -p /12.txt -p /12.txt -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\nhello world\n";
};

subtest "max-data-crapped" => sub {
    my $guard = spawn_server(trace => {});
    my $resp = `$cli -m 10 -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    undef $guard;
    sleep 2;
    # build list of filtered events
    open my $fh, "<", "$tempdir/events"
        or die "failed to open file $tempdir/events:$!";
    my $events = ":";
    while (my $line = <$fh>) {
        next unless $line =~ /^{/;
        my $event = from_json($line);
        if ($event->{type} =~ /^(send|receive|max-data-receive)$/) {
            $events .= "$event->{type}:";
        } elsif ($event->{type} eq 'stream-send') {
            $events .= "stream-send\@$event->{'stream-id'}:";
        }
    }
    # check that events are happening in expected order, without a busy loop to quicly_send
    like $events, qr/:send:stream-send\@0:receive:max-data-receive:send:stream-send\@0:/;
};

unlink "$tempdir/session";

subtest "0-rtt-vs-hrr" => sub {
    plan skip_all => "no support for x25519, we need multiple key exchanges to run this test"
        if `$cli -x x25519 2>&1` =~ /unknown key exchange/;
    my $guard = spawn_server(qw(-x x25519));
    my $resp = `$cli -x x25519 -x secp256r1 -s $tempdir/session -p /12.txt 127.0.0.1 $port 2> $tempdir/stderr.log; cat $tempdir/stderr.log`;
    like $resp, qr/^hello world\n/s;
    undef $guard;
    $guard = spawn_server(qw(-x secp256r1));
    $resp = `$cli -x x25519 -x secp256r1 -s $tempdir/session -p /12.txt 127.0.0.1 $port 2> $tempdir/stderr.log; cat $tempdir/stderr.log`;
    like $resp, qr/^hello world\n/s;
};

done_testing;

sub build_trace_cmd {
    my %args = (
        script => "$tempdir/dtrace.d",
        events => "$tempdir/events",
        @_,
    );
    my $trace_cmd = "rm -f $args{events}; exec sudo dtrace -s $args{script} -o $args{events}";
    if ($args{cmd}) {
        $trace_cmd .= " -c '$args{cmd}'";
    } elsif ($args{pid}) {
        $trace_cmd .= " -p $args{pid}";
    } else {
        die "neither of cmd nor pid is given";
    }
    $trace_cmd;
}

sub spawn_server {
    my %args = (
        opts  => [],
        trace => undef,
        @_,
    );
    my @cmd = ($cli, "-k", "t/assets/server.key", "-c", "t/assets/server.crt", @{$args{opts}}, "127.0.0.1", $port);
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        exec @cmd;
        die "failed to exec $cmd[0]:$?";
    }
    while (`netstat -na` !~ /^udp.*\s127\.0\.0\.1[\.:]$port\s/m) {
        if (waitpid($pid, WNOHANG) == $pid) {
            die "failed to launch server";
        }
        sleep 0.1;
    }
    if ($args{trace}) {
        system "@{[build_trace_cmd(%{$args{trace}}, pid => $pid)]} &";
        sleep 1;
    }
    return scope_guard(sub {
        kill 9, $pid;
        while (waitpid($pid, 0) != $pid) {}
    });
}

sub read_events {
    my $fn = $_[0] || "$tempdir/events";
    join "\n", grep { /^\{/ } split "\n", slurp_file($fn);
}

sub slurp_file {
    my $fn = shift;
    open my $fh, "<", $fn
        or die "failed to open file:$fn:$!";
    do {
        local $/;
        <$fh>;
    };
}

1;
