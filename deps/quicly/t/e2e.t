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

subtest "hello" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -e $tempdir/events -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    subtest "events" => sub {
        my $events = slurp_file("$tempdir/events");
        complex $events, sub {
            $_ =~ /"type":"transport-close-send",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)"/s
                and $1 eq 'packet-sent' and $2 eq 'send' and $3 eq 'free';
        };
    };
    # check if the client receives extra connection IDs
    subtest "initial-ncid" => sub {
        my $events = slurp_file("$tempdir/events");
        complex $events, sub {
            my @seen;
            my @expected = (0, 1, 1, 1); # expecting to see sequence=1,2,3 as we set active_connection_id_limit to 4
            foreach (split(/\n/)) {
                if ( /"type":"new-connection-id-receive",.*"sequence":([0-9]+),/ ) {
                    # $1 contains sequence number
                    $seen[$1] = 1;
                }
            }
            # check if @seen is equivalent to @expected
            if (scalar @seen != scalar @expected) {
                return 0;
            }
            for (my $i = 0; $i < scalar @seen; $i++) {
                if (not defined $seen[$i]) {
                    $seen[$i] = 0;
                }
                if ($seen[$i] != $expected[$i]) {
                    return 0;
                }
            }
            return 1;
        };
    };
};

subtest "datagram" => sub {
    my $guard = spawn_server("-D");
    my $resp = `$cli -D 127.0.0.1 $port 2> /dev/null`;
    like $resp, qr/^DATAGRAM: hello datagram!$/m;
};

subtest "version-negotiation" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -n -e $tempdir/events -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = slurp_file("$tempdir/events");
    if ($events =~ /"type":"connect",.*"version":(\d+)(?:.|\n)*"type":"version-switch",.*"new-version":(\d+)/m) {
        is $2, 0xff00001d;
        isnt $1, 0xff00001d;
    } else {
        fail "no quic-version-switch event";
        diag $events;
    }
};

subtest "retry" => sub {
    my $guard = spawn_server("-R");
    for my $version (qw(27 29)) {
        subtest "draft-$version" => sub {
            my $resp = `$cli -d $version -e $tempdir/events -p /12 127.0.0.1 $port 2> /dev/null`;
            is $resp, "hello world\n";
            my $events = slurp_file("$tempdir/events");
            unlike $events, qr/version-switch/, "no version switch";
            complex $events, sub {
                $_ =~ qr/"type":"receive",.*"first-octet":(\d+).*\n.*"type":"stream-lost",.*"stream-id":-1,.*"off":0,/ and $1 >= 240
            }, "CH deemed lost in response to retry";
        };
    }
};

subtest "large-client-hello" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -E -e $tempdir/events -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    my $events = slurp_file("$tempdir/events");
    complex $events, sub {
        my $before_receive = (split /"receive"/, $_)[0];
        $before_receive =~ /"stream-send".*?\n.*?"stream-send"/s;
    };
};

unlink "$tempdir/session";

subtest "0-rtt" => sub {
    my $guard = spawn_server();
    my $resp = `$cli -s $tempdir/session -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    ok -e "$tempdir/session", "session saved";
    system "$cli -s $tempdir/session -e $tempdir/events 127.0.0.1 $port > /dev/null 2>&1";
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"stream-send".*"stream-id":0,(.|\n)*"type":"packet-sent".*"pn":1,/m, "stream 0 on pn 1";
    like $events, qr/"type":"cc-ack-received".*"largest-acked":1,/m, "pn 1 acked";
};

unlink "$tempdir/session";

# obtain NEW_TOKEN token, rewrite it to Retry token (by trimming the saved file by one byte; this hack relies on the format of our
# session file storing the token at the beginning, and the type of the ticket being stored at the beginning of the token.
subtest "retry-invalid-token" => sub {
    my $guard = spawn_server("-R");
    # obtain NEW_TOKEN token
    my $resp = `$cli -s $tempdir/session -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    ok -e "$tempdir/session", "session saved";
    # rewrite the token stored in the session file to a broken Retry token
    my $session = slurp_file("$tempdir/session");
    my $type = ord substr $session, 2, 1;
    is $type, 1;
    open my $fh, '>', "$tempdir/session"
        or die "failed to open $tempdir/session:$!";
    print $fh substr $session, 0, 2;
    print $fh "\0"; # type = Retry
    print $fh substr $session, 3;
    close $fh;
    # reconnect
    $resp = `$cli -e $tempdir/events -s $tempdir/session -p /12 127.0.0.1 $port 2> /dev/null`;
    isnt $resp, "hello world\n", "not a valid response";
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"transport-close-receive",.*"error-code":11,.*"reason-phrase":"token decryption failure"/m, "received token decryption failure";
};

subtest "stateless-reset" => sub {
    my $guard = spawn_server(qw(-B deadbeef));
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
    $guard = spawn_server(qw(-B deadbeef));
    # wait for the child to die
    while (waitpid($pid, 0) != $pid) {
    }
    # check that the stateless reset is logged
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"stateless-reset-receive",/m, 'got stateless reset';
    unlike +($events =~ /"type":"stateless-reset-receive",.*?\n/ and $'), qr/"type":"packet-sent",/m, 'nothing sent after receiving stateless reset';
};

subtest "no-compatible-version" => sub {
    # spawn a server that sends empty VN
    my $sock = IO::Socket::INET->new(
        LocalAddr => "127.0.0.1:$port",
        Proto     => 'udp',
    ) or die "failed to listen to port $port:$!";
    # launch client
    open my $client, "-|", "$cli -e $tempdir/events 127.0.0.1 $port 2>&1"
        or die "failed to launch $cli:$!";
    # server sends a VN packet in response to client's packet
    while (1) {
        if (my $peer = $sock->recv(my $input, 1500, 0)) {
            my $server_cidl = ord substr $input, 5;
            my $server_cid = substr $input, 6, $server_cidl;
            my $client_cidl = ord substr $input, 6 + $server_cidl;
            my $client_cid = substr $input, 7, $client_cidl;
            $sock->send(sprintf("\x80\0\0\0\0" . '%c%s%c%s' . "\x0a\x0a\x0a\x0a", $client_cidl, $client_cid, $server_cidl, $server_cid), 0, $peer);
            last;
        }
    }
    # check the output of the client
    my $result = do {local $/; join "", <$client>};
    like $result, qr/no compatible version/;
    # check the trace
    my $events = slurp_file("$tempdir/events");
    like $events, qr/"type":"receive",/m, "one receive event";
    unlike +($events =~ /"type":"receive",.*?\n/ and $'), qr/"type":"packet-sent",/m, "nothing sent after receiving VN";
};

subtest "idle-timeout" => sub {
    my $guard = spawn_server(qw(-I 1000 -e), "$tempdir/server-events");
    my $resp = `$cli -e $tempdir/client-events -p /12 -i 2000 127.0.0.1 $port 2> /dev/null`;
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
    my $guard = spawn_server(qw(-X 2));
    my $resp = `$cli -p /12 -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\n";
    $resp = `$cli -p /12 -p /12 -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\n";
    $resp = `$cli -p /12 -p /12 -p /12 -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\nhello world\nhello world\nhello world\n";
};

subtest "max-data-crapped" => sub {
    my $guard = spawn_server('-e', "$tempdir/events");
    my $resp = `$cli -m 10 -p /12 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
    undef $guard;
    # build list of filtered events
    open my $fh, "<", "$tempdir/events"
        or die "failed to open file $tempdir/events:$!";
    my $events = ":";
    while (my $line = <$fh>) {
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
    my $resp = `$cli -x x25519 -x secp256r1 -s $tempdir/session -p /12 127.0.0.1 $port 2> $tempdir/stderr.log; cat $tempdir/stderr.log`;
    like $resp, qr/^hello world\n/s;
    undef $guard;
    $guard = spawn_server(qw(-x secp256r1));
    $resp = `$cli -x x25519 -x secp256r1 -s $tempdir/session -p /12 127.0.0.1 $port 2> $tempdir/stderr.log; cat $tempdir/stderr.log`;
    like $resp, qr/^hello world\n/s;
};

subtest "alpn" => sub {
    my $guard = spawn_server(qw(-a hq-23));
    my $resp = `$cli -p /12 127.0.0.1 $port 2>&1`;
    like $resp, qr/transport close:code=0x178;/, "no ALPN";
    $resp = `$cli -a hq-23 -p /12 127.0.0.1 $port 2>&1`;
    like $resp, qr/^hello world$/m, "ALPN match";
    $resp = `$cli -a hX-23 -p /12 127.0.0.1 $port 2>&1`;
    like $resp, qr/transport close:code=0x178;/, "ALPN mismatch";
};

subtest "key-update" => sub {
    my $doit = sub {
        my ($server_opts, $client_opts, $doing_updates) = @_;
        my $guard = spawn_server(@$server_opts, "-e", "$tempdir/events");
        # ensure at least 30 round-trips
        my $stats = `exec $cli -p /120000 -M 4000 @{[join " ", @$client_opts]} 127.0.0.1 $port 2>&1 > $tempdir/resp`;
        is do {
            open my $fh, "<", "$tempdir/resp"
                or die "failed to open file:$tempdir/resp:$!";
            local $/;
            <$fh>;
        }, "hello world\n" x 10000, "response";
        like $stats, qr/,\s*packets-decryption-failed:\s*0,/, "no decryption errors";
        undef $guard;
        my $num_key_updates = do {
            my $loglines = do {
                open my $fh, "<", "$tempdir/events"
                    or die "failed to open file:$tempdir/events:$!";
                local $/;
                <$fh>;
            };
            () = $loglines =~ /{"type":"crypto-send-key-update",/sg;
        };
        if ($doing_updates) {
            cmp_ok($num_key_updates, ">=", 4);
        } else {
            is $num_key_updates, 0;
        }
    };
    subtest "none" => sub {
        $doit->([], [], undef);
    };
    subtest "client" => sub {
        $doit->([], [qw(-K 1)], 1);
    };
    subtest "server" => sub {
        $doit->([qw(-K 1)], [], 1);
    };
    subtest "both" => sub {
        $doit->([qw(-K 1)], [qw(-K 1)], 1);
    };
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

1;
