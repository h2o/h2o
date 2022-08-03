#! /usr/bin/env perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use JSON;
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
    my $resp = `$cli -j $tempdir/events -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";

    subtest "events" => sub {
        my $events_jsonl = slurp_file("$tempdir/events");
        diag("raw events:\n$events_jsonl") if $ENV{TEST_DEBUG};

        my @events = map { decode_json($_) } split /\n/, $events_jsonl;

        my ($event) = find_event(\@events, "quicly", "connect");
        ok $event, "quicly:connect exists";
        is $event->{version}, 1;

        ($event) = find_event(\@events, "quicly", "free");
        ok $event, "quicly:free exists";
    };

    subtest "qlog-adapter", sub {
        my $qlog = `misc/qlog-adapter.py < $tempdir/events`;
        is $?, 0, "qlog-adapter can transform raw event logs";
        diag("qlog:\n$qlog") if $ENV{TEST_DEBUG};
        my @events = map { decode_json($_) } split /\n/, $qlog;
        cmp_ok scalar(@events), ">=", 2, "it has at least two events";
        # TODO: validate the events according to the qlog spec
    };
};


done_testing;

sub find_event {
    my($events, $module, $type) = @_;

    my @results;
    for my $event (@$events) {
        if ($event->{module} eq $module && $event->{type} eq $type) {
            push @results, $event;
        }
    }
    return @results;
}

sub spawn_server {
    my @cmd;
    if (grep(/^-W$/, @_)) {
        @cmd = ($cli, "-k", "t/assets/ec256-key-pair.pem", "-c", "t/assets/ec256-pub.pem", @_, "127.0.0.1", $port);
    } else {
        @cmd = ($cli, "-k", "t/assets/server.key", "-c", "t/assets/server.crt", @_, "127.0.0.1", $port);
    }
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

1;
