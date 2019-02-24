#! /usr/bin/perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use POSIX ":sys_wait_h";
use Scope::Guard qw(scope_guard);
use Test::More;
use Time::HiRes qw(sleep);

$ENV{BINARY_DIR} ||= ".";
my $cli = "$ENV{BINARY_DIR}/cli";
my $port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $tempdir = tempdir(CLEANUP => 1);

subtest "hello" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -e $tempdir/events -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    subtest "events" => sub {
        my $events = slurp_file("$tempdir/events");
        ok +($events =~ /"type":"transport-close-send",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)"/s
             and $1 eq "packet-commit" and $2 eq "quictrace-sent" and $3 eq "send" and $4 eq "free");
    };
};

subtest "version-negotiation" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -n -e $tempdir/events -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = slurp_file("$tempdir/events");
    if ($events =~ /"type":"connect",.*"quic-version":(\d+)(?:.|\n)*"type":"quic-version-switch",.*"quic-version":(\d+)/m) {
        is $2, 0xff000011;
        isnt $1, 0xff000011;
    } else {
        fail "no quic-version-switch event";
        diag $events;
    }
};

subtest "retry" => sub {
    my $guard = spawn_server("-R");
    my $resp = `$cli -e $tempdir/events -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"receive",.*"first-octet":245.*\n.*"type":"stream-lost",.*"stream-id":-1,.*"off":0,/, "CH deemed lost in response to retry";
};

subtest "0-rtt" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -s $tempdir/session -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    ok -e "$tempdir/session", "session saved";
    system "$cli -s $tempdir/session -e $tempdir/events 127.0.0.1 $port > /dev/null 2>&1";
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"stream-send".*"stream-id":0,(.|\n)*"type":"packet-commit".*"pn":1,/m, "stream 0 on pn 1";
    like $events, qr/"type":"cc-ack-received".*"pn":1,/m, "pn 1 acked";
};

subtest "stateless-reset" => sub {
    my $guard = spawn_server(qw(-C deadbeef));
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # child process
        open STDOUT, '>', '/dev/null'
            or die "failed to redirect stdout to /dev/null:$!";
        exec $cli, '-e', "$tempdir/events", qw(-i 3000 127.0.0.1), $port;
        die "failed to exec $cli:$!";
    }
    # parent process, let the client fetch the first response, then kill respawn the server using same CID encryption key
    sleep 1;
    undef $guard;
    $guard = spawn_server(qw(-C deadbeef));
    # wait for the child to die
    while (waitpid($pid, 0) != $pid) {
    }
    # check that the stateless reset is logged
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"stateless-reset-receive",/m;
};

subtest "blocked-streams" => sub {
    my $guard = spawn_server(qw(-X 2));
    my $resp = `$cli -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\n";
    $resp = `$cli -p /12.txt -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\n";
    $resp = `$cli -p /12.txt -p /12.txt -p /12.txt -p /12.txt 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\nhello world\n";
};

done_testing;

sub spawn_server {
    my @cmd = ($cli, "-k", "t/assets/server.key", "-c", "t/assets/server.crt", @_, "127.0.0.1", $port);
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
    return scope_guard(sub {
        kill 9, $pid;
        while (waitpid($pid, 0) != $pid) {}
    });
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
