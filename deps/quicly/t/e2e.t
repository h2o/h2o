#! /usr/bin/env perl

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use JSON;
use Net::EmptyPort qw(empty_port);
use POSIX ":sys_wait_h";
use Test::More;
use Time::HiRes qw(sleep time);

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
my $udpfw = "$ENV{BINARY_DIR}/udpfw";
my $port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});
my $udpfw_port = empty_port({
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
            $_ =~ /"type":"transport_close_send",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)",.*?"type":"([^\"]*)"/s
                and $1 eq 'packet_sent' and $2 eq 'send' and $3 eq 'free';
        };

        # check that the events are compatible with qlog-adapter
        subtest "qlog-adapter" => sub {
            plan skip_all => "python3 not found"
                unless system("which python3 > /dev/null 2>&1") == 0;
            my $qlog = `misc/qlog-adapter.py < $tempdir/events`;
            is $?, 0, "qlog-adapter can transform raw event logs";
            diag("qlog:\n$qlog") if $ENV{TEST_DEBUG};
            my @events = map { decode_json($_) } split /\n/, $qlog;
            cmp_ok scalar(@events), ">=", 2, "it has at least two events";

            # https://github.com/quicwg/qlog/blob/main/draft-ietf-quic-qlog-main-schema.md#the-high-level-qlog-schema-top-level
            ok $events[0]->{qlog_version}, "it has qlog_version";
            # TODO: validate the events according to the qlog schema
        };
    };

    # check if the client receives extra connection IDs
    subtest "initial-ncid" => sub {
        my $events = slurp_file("$tempdir/events");
        complex $events, sub {
            my @seen;
            my @expected = (0, 1, 1, 1); # expecting to see sequence=1,2,3 as we set active_connection_id_limit to 4
            foreach (split(/\n/)) {
                if ( /"type":"new_connection_id_receive",.*"sequence":([0-9]+),/ ) {
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
    if ($events =~ /"type":"connect",.*"version":(\d+)(?:.|\n)*"type":"version_switch",.*"new_version":(\d+)/m) {
        is $2, 1;
        isnt $1, 1;
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
                $_ =~ qr/"type":"receive",.*"bytes":"([0-9A-Fa-f]{2}).*\n.*"type":"stream_lost",.*"stream_id":-1,.*"off":0,/ and hex($1) >= 240
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
        $before_receive =~ /"stream_send".*?\n.*?"stream_send"/s;
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
    like $events, qr/"type":"stream_send".*"stream_id":0,(.|\n)*"type":"packet_sent".*"pn":1,/m, "stream 0 on pn 1";
    like $events, qr/"type":"cc_ack_received".*"largest_acked":1,/m, "pn 1 acked";
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
    like $events, qr/"type":"transport_close_receive",.*"error_code":11,.*"reason_phrase":"token decryption failure"/m, "received token decryption failure";
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
    like $events, qr/"type":"stateless_reset_receive",/m, 'got stateless reset';
    unlike +($events =~ /"type":"stateless_reset_receive",.*?\n/ and $'), qr/"type":"packet_sent",/m, 'nothing sent after receiving stateless reset';
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
    like slurp_file("$tempdir/client-events"), qr/"type":("idle_timeout"|"stateless_reset_receive"),/m;
    like slurp_file("$tempdir/server-events"), qr/"type":"idle_timeout",/m;
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
        if ($event->{type} =~ /^(send|receive|max_data_receive)$/) {
            $events .= "$event->{type}:";
        } elsif ($event->{type} eq 'stream_send') {
            $events .= "stream_send\@$event->{stream_id}:";
        }
    }
    # check that events are happening in expected order, without a busy loop to quicly_send
    like $events, qr/:send:stream_send\@0:receive:max_data_receive:send:stream_send\@0:/;
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
            () = $loglines =~ /,"type":"crypto_send_key_update",/sg;
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

subtest "raw-certificates-ec" => sub {
    my $guard = spawn_server(qw(-W -));
    my $resp = `$cli -p /12 -W t/assets/ec256-pub.pem 127.0.0.1 $port 2> /dev/null`;
    is $resp, "hello world\n";
};

subtest "path-migration" => sub {
    my $doit = sub {
        my @client_opts = @_;
        my $server_guard = spawn_server("-e", "$tempdir/events");
        my $udpfw_guard = undef;
        my $respawn_udpfw = sub {
            $udpfw_guard = undef; # terminate existing process
            $udpfw_guard = spawn_process(
                ["sh", "-c", "exec $udpfw -b 100 -i 1 -p 0 -B 100 -I 1 -P 10000 -l $udpfw_port 127.0.0.1 $port > /dev/null 2>&1"],
                $udpfw_port,
            );
        };
        $respawn_udpfw->();
        # spawn client that sends one request every second, recording events to file
        my $pid = fork;
        die "fork failed:$!"
            unless defined $pid;
        if ($pid == 0) {
            exec $cli, @client_opts, qw(-O -i 1000 -p /10000 127.0.0.1), $udpfw_port;
            die "exec $cli failed:$!";
        }
        # send two USR1 signals, each of them causing path migration between requests
        sleep .5;
        $respawn_udpfw->();
        sleep 2;
        $respawn_udpfw->();
        sleep 2;
        # kill the peers
        kill 'TERM', $pid;
        while (waitpid($pid, 0) != $pid) {}
        sleep 0.5; # wait for server-side to close and emit stats
        my $server_output = $server_guard->finalize;
        # read the log
        my $log = slurp_file("$tempdir/events");
        # check that the path has migrated twice
        like $log, qr{"type":"promote_path".*\n.*"type":"promote_path"}s;
        subtest "CID seq 1 is used for 1st path probe" => sub {
            plan skip_all => "zero-length CID"
                unless @client_opts;
            complex $log, sub {
                /"type":"new_connection_id_receive",[^\n]*"sequence":1,[^\n]*"cid":"(.*?)"/s;
                my $cid1 = $1;
                /"type":"packet_prepare",[^\n]*"dcid":"([^\"]*)"[^\n]*\n[^\n]*"type":"path_challenge_send",/s;
                my $cid_probe = $1;
                $cid1 eq $cid_probe;
            };
        };
        # check that packets are lost (or deemed lost), but that CC is in slow start
        complex $server_output, sub {
            /packets-lost:\s*(\d+).*num-loss-episodes:\s*(\d+)/ and $1 >= 2 and $2 == 0;
        }, "packets-lost-but-cc-in-slow-start";

    };
    subtest "without-cid" => sub {
        $doit->();
    };
    subtest "with-cid" => sub {
        $doit->(qw(-B 01234567));
    };
};

subtest "slow-start" => sub {
    # spawn udpfw that applies 100ms RTT but otherwise nothing
    my $udpfw_guard = spawn_process(
        ["sh", "-c", "exec $udpfw -b 100 -i 1 -p 0 -B 100 -I 1 -P 100000 -l $udpfw_port 127.0.0.1 $port > /dev/null 2>&1"],
        $udpfw_port,
    );

    # read first $size bytes from client $cli (which would be the payload received) and check RT
    my $doit = sub {
        my ($size, $rt_min, $rt_max, @cli_args) = @_;
        subtest "${size}B" => sub {
            my $start_at = time;
            open my $fh, "-|", "$cli -p /$size @{[ join ' ', @cli_args ]} 127.0.0.1 $udpfw_port 2>&1"
                or die "failed to launch $cli:$!";
            for (my $total_read = 0; $total_read < $size;) {
                IO::Select->new($fh)->can_read(); # block until the command writes something
                my $nread = sysread $fh, my $buf, 65536;
                die "failed to read from pipe, got $nread:$!"
                    unless $nread > 0;
                $total_read += $nread;
            }
            my $elapsed = time - $start_at;
            diag $elapsed;
            cmp_ok $rt_min * 0.1, '<=', $elapsed, "RT >= $rt_min";
            cmp_ok $rt_max * 0.1, '>=', $elapsed, "RT <= $rt_max";
        };
    };

    my $each_cc = sub {
        my $cb = shift;
        for my $cc (qw(reno pico cubic)) {
            subtest $cc => sub {
                $cb->($cc);
            };
        }
    };

    subtest "no-pacing" => sub {
        $each_cc->(sub {
            my $cc = shift;
            subtest "respect-app-limited" => sub {
                plan skip_all => "Cubic TODO respect app-limited"
                    if $cc eq "cubic";
                my $guard = spawn_server("-C", "$cc:10");
                # tail of 1st, 2nd, and 3rd batch fits into each round trip
                $doit->(@$_)
                    for ([14000, 2, 2.5], [45000, 3, 3.5], [72000, 4, 4.5]);
            };
            subtest "disregard-app-limited" => sub {
                my $guard = spawn_server("-C", "$cc:10", "--disregard-app-limited");
                # tail of 1st, 2nd, and 3rd batch fits into each round trip
                $doit->(@$_)
                    for ([16000, 2, 2.5], [48000, 3, 3.5], [72000, 4, 4.5]);
            };
        });
    };

    subtest "pacing" => sub {
        $each_cc->(sub {
            my $cc = shift;
            subtest "respect-app-limited" => sub {
                plan skip_all => "Cubic TODO respect app-limited"
                    if $cc eq "cubic";
                my $guard = spawn_server("-C", "$cc:20:p");
                # check head of 1st and 3rd batch, tail of 1st and 2nd
                $doit->(@$_)
                    for ([1000, 2, 2.3], [28000, 2.3, 3], [85000, 3.3, 4], [89000, 4, 4.5]);
            };
            subtest "disregard-app-limited" => sub {
                my $guard = spawn_server("-C", "$cc:20:p", "--disregard-app-limited");
                # tail of 1st, 2nd, and 3rd batch fits into each round trip
                $doit->(@$_)
                    for ([1000, 2, 2.3], [30000, 2.3, 3], [87000, 3.3, 4], [96000, 4, 4.5]);
            };
        });
    };

    subtest "jumpstart" => sub {
        $each_cc->(sub {
            my $cc = shift;
            plan skip_all => "Cubic TODO respect app-limited (mandatory for jumpstart)"
                if $cc eq "cubic";
            my $guard = spawn_server("-C", "$cc:20:p", "--jumpstart-default", "80");
            $doit->(@$_)
                for ([1450 * 45, 2.45, 2.8], [1450 * 90, 3.0, 3.3]);
        });
    };

    subtest "jumpstart-resume" => sub {
        $each_cc->(sub {
            my $cc = shift;
            plan skip_all => "Cubic TODO respect app-limited (mandatory for jumpstart)"
                if $cc eq "cubic";
            unlink "$tempdir/session";
            my $guard = spawn_server("-C", "$cc:10:p", "--jumpstart-max", "80");
            # test RT without jumpstart
            $doit->(100000, 4, 5);
            # train
            my $pid = fork;
            die "fork failed:$!"
                unless defined $pid;
            if ($pid == 0) {
                open STDOUT, ">", "/dev/null"
                    or die "failed to redirect STDOUT to /dev/null:$!";
                exec $cli, qw(-p /1000000 -i 5000 -s), "$tempdir/session", "127.0.0.1", $udpfw_port;
                die "failed to exec $cli:$!";
            }
            sleep 2; # wait until the connection becomes idle, at which point the token will be sent
            kill 'KILL', $pid;
            while (waitpid($pid, 0) != $pid) {}
            # test RT using the obtained session information
            $doit->(100000, 2, 2.999, "-s", "$tempdir/session");
        });
    };
};

subtest "trasport-parameters" => sub {
    my $guard = spawn_server();

    subtest "max-udp-payload-size" => sub {
        my $do_test = sub {
            my $max_payload_size = shift;
            my $expected_max_payload_size = shift;
            # we use the forwarder just to print the size of the packets
            my $udpfw_guard = spawn_process(
                ["sh", "-c", "exec $udpfw -b 100 -i 1 -p 0 -B 100 -I 1 -l $udpfw_port 127.0.0.1 $port > $tempdir/udpfw.events 2>&1"],
                $udpfw_port,
            );
            my $resp = `$cli -e $tempdir/events -U $max_payload_size -p /12 127.0.0.1 $udpfw_port 2> /dev/null`;
            is $resp, "hello world\n";
            $udpfw_guard = undef;
            open(my $fh, '<', "$tempdir/udpfw.events") or die "failed to open file: $!";
            my $server_packets = 0;
            while (my $line = <$fh>) {
                if ($line =~ /^[^:]+:[^:]+:d:forward:(\d+)/) {
                    $server_packets++;
                    if ($server_packets == 1) {
                        is $1, $expected_max_payload_size, 'First packet size is equal to expected max payload size';
                    } else {
                        cmp_ok $1, '<=', $expected_max_payload_size, 'Packet size is lower or equal to expected max payload size';
                    }
                }
            }
            cmp_ok $server_packets, '>', 0, "We have seen packets from the server";
        };
        $do_test->(1252, 1252);
        $do_test->(1200, 1200);
        $do_test->(1300, 1280);
    };
};

subtest "reset-stream-overflow" => sub {
    my $server = spawn_server();
    my $conn = RawConnection->new("127.0.0.1", $port);
    $conn->send("\x04\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"); # reset stream with final_size=QUICINT_MAX
    sleep 0.5;
    ok !$server->is_dead(), "server process must be alive";
    my $received = $conn->receive();
    like $received, qr/^\x1c\x03\x04/, "responds with CONNECTION_CLOSE(FLOW_CONTROL_ERROR) for RESET_STREAM";
};

subtest "stream-open-after-connection-close" => sub {
    my $server = spawn_server(qw(-e /dev/stderr));
    my $conn = RawConnection->new("127.0.0.1", $port);
    $conn->send("\x1c\x00\x00\x00" . "\x0a\x00\x05hello"); # CONNECTION_CLOSE -> STREAM
    sleep 0.5;
    ok !$server->is_dead(), "server process must be alive";
    is `$cli -I 1000 -p /12 127.0.0.1 $port 2> /dev/null`, "hello world\n", "server is responding";
};

subtest "invalid-ack" => sub {
    my $server = spawn_server();
    subtest "gap" => sub {
        my $conn = RawConnection->new("127.0.0.1", $port);
        my $pn = $conn->largest_pn_received;
        $conn->send("\x02" . chr($pn) . "\x00\x00" . chr($pn)); # ACK all PNs up to largest_pn_received
        sleep 0.5;
        ok !$server->is_dead(), "server is alive";
        my $received = $conn->receive();
        like $received, qr/^\x1c\x0a\x02/, "responds with CONNECTION_CLOSE(PROTOCOL_VIOLATION) for ACK";
    };
    subtest "too large" => sub {
        my $conn = RawConnection->new("127.0.0.1", $port);
        $conn->send("\x02\x3f\x00\x00\x00"); # ACK pn=63, server would not have sent so many packets
        sleep 0.5;
        ok !$server->is_dead(), "server is alive";
        my $received = $conn->receive();
        like $received, qr/^\x1c\x0a\x02/, "responds with CONNECTION_CLOSE(PROTOCOL_VIOLATION) for ACK";
    };
};

done_testing;

sub spawn_server {
    my @cmd;
    if (grep(/^-W$/, @_)) {
        @cmd = ($cli, "-k", "t/assets/ec256-key-pair.pem", "-c", "t/assets/ec256-pub.pem", @_, "127.0.0.1", $port);
    } else {
        @cmd = ($cli, "-k", "t/assets/server.key", "-c", "t/assets/server.crt", @_, "127.0.0.1", $port);
    }
    spawn_process(\@cmd, $port);
}

package SpawnedProcess {
    use POSIX ":sys_wait_h";

    sub new {
        my ($klass, $cmd, $listen_port) = @_;

        my $self = bless {
            logfh => scalar File::Temp::tempfile(),
            pid   => fork(),
        }, $klass;

        die "fork failed:$!"
        unless defined $self->{pid};
        if ($self->{pid} == 0) {
            close STDOUT;
            open STDOUT, ">&", $self->{logfh}
                or die "failed to dup(2) log file to STDOUT:$!";
            open STDERR, ">&", $self->{logfh}
                or die "failed to dup(2) log file to STDERR:$!";
            exec @$cmd;
            die "failed to exec @{[$cmd->[0]]}:$?";
        }
        for (1..10) {
            if (`netstat -na` =~ /^udp.*\s(127\.0\.0\.1|0\.0\.0\.0|\*)[\.:]$listen_port\s/m) {
                last;
            }
            if (waitpid($self->{pid}, WNOHANG) == $self->{pid}) {
                die "failed to launch @{[$cmd->[0]]}:$?";
            }
            sleep 0.1;
        }

        $self;
    }

    sub DESTROY {
        goto \&finalize;
    }

    sub is_dead {
        my $self = shift;

        return 1
            unless $self->{pid};

        my $dead = waitpid($self->{pid}, WNOHANG) > 0;
        undef $self->{pid}
            if $dead;
        $dead;
    }

    sub finalize {
        my $self = shift;

        # kill the process, if it is still alive
        if ($self->{pid}) {
            kill 9, $self->{pid};
            while (waitpid($self->{pid}, 0) != $self->{pid}) {}
            undef $self->{pid};
        }

        # fetch and close the log file
        seek $self->{logfh}, 0, 0;
        my $log = do {
            local $/;
            readline $self->{logfh};
        };
        close $self->{logfh};

        print STDERR $log;

        return $log;
    }
}

sub spawn_process {
    SpawnedProcess->new(@_);
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

package RawConnection {
    use Fcntl qw(F_GETFD F_SETFD FD_CLOEXEC);
    use JSON qw(decode_json);
    use Socket qw(SOCK_DGRAM IPPROTO_UDP inet_aton pack_sockaddr_in);

    sub new {
        my ($klass, $host, $port) = @_;

        my $self = bless {
            sock     => do {
                IO::Socket::INET->new(
                    Type   => SOCK_DGRAM,
                    Proto  => IPPROTO_UDP,
                ) or die "failed to open socket:$!";
            },
            peeraddr => pack_sockaddr_in($port, inet_aton($host)),
            pn       => 256,   # whatever large enough to avoid collision with those used during the handshake
            largest_pn_received => -1,
        }, $klass;

        # perform handshake and obtain connection parameters
        fcntl($self->{sock}, F_SETFD, 0)
            or die "failed to drop FD_CLOEXEC:$!";
        open(
            my $fh,
            "-|",
            $cli, "--sockfd", fileno($self->{sock}), qw(-y aes128gcmsha256 -e /dev/stdout --exit-after-handshake),
            $host, $port,
        ) or die "failed to spawn $cli:$!";
        fcntl($self->{sock}, F_SETFD, FD_CLOEXEC)
            or die "failed to re-add FD_CLOEXEC:$!";
        while (my $line = <$fh>) {
            chomp $line;
            my $event = decode_json $line;
            if ($event->{type} eq 'receive') {
                if (!defined $self->{server_cid}) {
                    $event->{bytes} =~ /^..000000010008(.{16})/
                        or die "invalid CID lengths found in packet:$event->{bytes}";
                    $self->{server_cid} = pack "H*", $1;
                }
            } elsif ($event->{type} eq 'crypto_update_secret' && $event->{epoch} == 3) {
                ($event->{is_enc} ? $self->{enc_secret} : $self->{dec_secret}) = $event->{secret};
            } elsif ($event->{type} eq 'packet_received') {
                $self->{largest_pn_received} = $event->{pn}
                    if $self->{largest_pn_received} < $event->{pn};
            }
        }
        close $fh
            or die "$cli failed with exit status:$?";

        $self;
    }

    sub largest_pn_received {
        my $self = shift;
        $self->{largest_pn_received};
    }

    sub send {
        my ($self, $payload) = @_;

        my $cleartext = join("",
            "\x41",                    # first byte (pnlen=2)
            $self->{server_cid},
            pack("n", ++$self->{pn}),
            $payload,
            "\0" x 20,                 # space enough for header protection entropy and AEAD tag,
        );
        my $encrypted = $self->transform_packet(1, $cleartext);
        $self->{sock}->send($encrypted, 0, $self->{peeraddr});
    }

    sub receive {
        my $self = shift;

        recv($self->{sock}, my $encrypted, 1500, 0)
            or return;
        $self->transform_packet(0, $encrypted);
    }

    sub transform_packet {
        my ($self, $is_enc, $input) = @_;
        my $tmpfh = File::Temp->new();

        print $tmpfh $input;
        $tmpfh->flush();

        my $mode = $is_enc ? "enc" : "dec";
        my $dcid_len = $is_enc ? 8 : 0;
        open my $fh, "$cli --${mode}rypt-packet @{[$self->{$mode . '_secret'}]}:$dcid_len < $tmpfh |"
            or die "failed to run $cli:$!";
        local $/;
        <$fh>;
    }

}

1;
