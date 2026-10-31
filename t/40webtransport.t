use strict;
use warnings;
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;
use File::Temp ();
use JSON::PP ();

my $client_prog = bindir() . "/webtransport-client";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

sub spawn_wt_server {
    my ($enabled, $extra) = @_;
    $extra //= '';
    spawn_h2o(<< "EOT");
webtransport: @{[ $enabled ? "ON" : "OFF" ]}
${extra}hosts:
  default:
    paths:
      /echo:
        webtransport.echo: ON
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
}

# h3 with the handshakes of earlier drafts, as current browsers send them: draft-02 (Chrome, Firefox), draft-07 and draft-14
# (Safari)
my @protocols = (
    { name => "h2", opts => "", port => sub { $_[0]->{tls_port} } },
    { name => "h3", opts => "-3", port => sub { $_[0]->{quic_port} } },
    map { { name => "h3-draft$_", opts => "-3 -d $_", port => sub { $_[0]->{quic_port} } } } (2, 7, 14),
);

# runs the client, returning its output as an arrayref of lines, and the exit status
sub run_client {
    my ($server, $proto, $opts, $path, @actions) = @_;
    my $url = "https://127.0.0.1:@{[ $proto->{port}->($server) ]}$path";
    my $cmd = join " ", $client_prog, $proto->{opts}, $opts, "'$url'", map { "'$_'" } @actions;
    my $out = `$cmd 2> /dev/null`;
    my $status = $? >> 8;
    diag "$cmd:\n$out" if $ENV{TEST_DEBUG};
    return ([split /\n/, $out], $status);
}

# checks that the output contains all the expected lines, regardless of their order (the order of events on different streams is
# not deterministic)
sub has_lines {
    my ($out, $expected, $name) = @_;
    my %seen = map { $_ => 1 } @$out;
    my @missing = grep { !$seen{$_} } @$expected;
    ok !@missing, $name or diag "missing: @{[ join ', ', map { qq{'$_'} } @missing ]}\noutput:\n@{[ join qq{\n}, @$out ]}";
}

my $server = spawn_wt_server(1);

for my $proto (@protocols) {
    my $is_h3 = $proto->{name} =~ /^h3/;
    my $first_bidi = $is_h3 ? 4 : 0;           # stream 0 is the CONNECT stream in HTTP/3
    my $first_server_uni = $is_h3 ? 15 : 3;    # 3, 7, 11 are the control and QPACK streams in HTTP/3

    subtest $proto->{name} => sub {
        subtest "echo" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi:hello", "uni:world", "dgram:dg1");
            is $status, 0, "exit status";
            has_lines($out, [
                "response 200",
                "client-bidi[$first_bidi] fin \"hello\"",
                "server-uni[$first_server_uni] fin \"world\"",
                "datagram \"dg1\"",
                "done",
            ], "echoed");
            has_lines($out, ["settings wt-enabled=1"], "settings") if $is_h3;
        };

        subtest "large" => sub {
            # the size is limited for HTTP/2 by the default receive window of the stream (256KB) that the server advertises
            my $size = $is_h3 ? 1000000 : 200000;
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi:\@$size", "bidi:\@$size");
            is $status, 0, "exit status";
            has_lines($out, [
                "client-bidi[$first_bidi] fin <$size bytes, pattern ok>",
                "client-bidi[@{[ $first_bidi + 4 ]}] fin <$size bytes, pattern ok>",
            ], "echoed");
        };

        subtest "server-initiated streams" => sub {
            my ($out, $status) = run_client($server, $proto, "-e 4", "/echo?open-bidi=2&open-uni=2");
            is $status, 0, "exit status";
            has_lines($out, [
                "server-bidi[1] fin \"stream 1\\n\"",
                "server-bidi[5] fin \"stream 5\\n\"",
                "server-uni[$first_server_uni] fin \"stream $first_server_uni\\n\"",
                "server-uni[@{[ $first_server_uni + 4 ]}] fin \"stream @{[ $first_server_uni + 4 ]}\\n\"",
            ], "received");
        };

        subtest "server-initiated streams opened from a timer" => sub {
            # written outside the handling of any input, the data must still be sent at once rather than at the next packet or
            # timeout of the connection
            my $started = Time::HiRes::time;
            my ($out, $status) = run_client($server, $proto, "-e 2", "/echo?open-uni=2&delay=100");
            is $status, 0, "exit status";
            has_lines($out, [
                "server-uni[$first_server_uni] fin \"stream $first_server_uni\\n\"",
                "server-uni[@{[ $first_server_uni + 4 ]}] fin \"stream @{[ $first_server_uni + 4 ]}\\n\"",
            ], "received");
            cmp_ok Time::HiRes::time - $started, '<', 2, "without waiting for a timeout";
        };

        subtest "reset and stop-sending are mirrored" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi-reset:7", "bidi-stop:9");
            is $status, 0, "exit status";
            has_lines($out, [
                "client-bidi[$first_bidi] reset 7",
                "client-bidi[@{[ $first_bidi + 4 ]}] stop-sending 9",
                "client-bidi[@{[ $first_bidi + 4 ]}] reset 9",
            ], "mirrored");
        };

        subtest "server drains" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo?drain", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["drain", "client-bidi[$first_bidi] fin \"x\""], "drained");
        };

        subtest "server closes" => sub {
            my ($out, $status) = run_client($server, $proto, "-w", "/echo?close=42", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["close 42 \"bye\""], "closed");
        };

        subtest "client drains" => sub {
            my ($out, $status) = run_client($server, $proto, "-w", "/echo", "drain");
            is $status, 0, "exit status";
            has_lines($out, ["close 0 \"\""], "server closes in response");
        };

        subtest "client closes" => sub {
            my ($out, $status) = run_client($server, $proto, "-c 5", "/echo", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["client-bidi[$first_bidi] fin \"x\"", "done"], "closed");
        };

        subtest "not a WebTransport endpoint" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/nope");
            is $status, 0, "exit status";
            has_lines($out, ["response 404"], "rejected");
        };
    };
}

subtest "disabled" => sub {
    my $server = spawn_wt_server(0);
    subtest "h2" => sub {
        my ($out) = run_client($server, $protocols[0], "-t 5000", "/echo", "bidi:x");
        ok !grep({ $_ eq "response 200" } @$out), "not established" or diag join "\n", @$out;
    };
    subtest "h3" => sub {
        my ($out) = run_client($server, $protocols[1], "-t 5000", "/echo", "bidi:x");
        has_lines($out, ["settings wt-enabled=0"], "not advertised");
        ok !grep({ $_ eq "response 200" } @$out), "not established";
    };
};

subtest "earlier drafts turned off" => sub {
    my $server = spawn_wt_server(1, "webtransport-legacy-drafts: OFF\n");
    for my $draft (2, 7, 14) {
        subtest "draft-$draft" => sub {
            my ($out) = run_client($server, { opts => "-3 -d $draft", port => sub { $_[0]->{quic_port} } }, "-t 5000", "/echo",
                                   "bidi:x");
            has_lines($out, ["settings wt-enabled=0"], "not advertised");
            ok !grep({ $_ eq "response 200" } @$out), "not established" or diag join "\n", @$out;
        };
    }
    subtest "draft-16" => sub {
        my ($out, $status) = run_client($server, $protocols[1], "", "/echo", "bidi:hello");
        is $status, 0, "exit status";
        has_lines($out, ["settings wt-enabled=1", "response 200", "client-bidi[4] fin \"hello\""], "still established");
    };
};

# Some clients send draft 16's SETTINGS_WT_ENABLED with the earlier drafts' and :protocol "webtransport", but no reset_stream_at (or
# only its provisional codepoint). They are served as the earlier draft.
subtest "a client of draft 16 and an earlier draft, without reset_stream_at" => sub {
    my $server = spawn_wt_server(1);
    my ($out, $status) = run_client($server, { opts => "-3 -d 2 -y", port => sub { $_[0]->{quic_port} } }, "", "/echo",
                                    "bidi:hello");
    is $status, 0, "exit status";
    has_lines($out, ["response 200", "client-bidi[4] fin \"hello\""], "served as draft 2");
    my $off = spawn_wt_server(1, "webtransport-legacy-drafts: OFF\n");
    ($out) = run_client($off, { opts => "-3 -d 2 -y", port => sub { $_[0]->{quic_port} } }, "-t 5000", "/echo", "bidi:x");
    has_lines($out, ["response 400"], "refused without the earlier drafts");
};

subtest "graceful shutdown" => sub {
    for my $proto (@protocols) {
        subtest $proto->{name} => sub {
            my $server = spawn_wt_server(1);
            my $url = "https://127.0.0.1:@{[ $proto->{port}->($server) ]}/echo";
            open my $fh, "-|", "$client_prog $proto->{opts} -w '$url' bidi:hi 2> /dev/null"
                or die "failed to spawn $client_prog: $!";
            sleep 3;
            kill 'TERM', $server->{pid};
            my @out = map { chomp; $_ } <$fh>;
            close $fh;
            is $? >> 8, 0, "exit status";
            has_lines(\@out, ["drain", "close 0 \"\""], "drained, then closed by the handler");
        };
    }
};

# The STOP_SENDING and RESET_STREAM frames of the streams of a session that has ended (but for a send side with bytes to send) are
# sent once the peer has the end of the session: Chrome, given the STOP_SENDING ahead of the end of the session while a read is
# pending on an incoming unidirectional stream, never settles `WebTransport.closed` (https://crbug.com/579037664). `uni-open` leaves
# such a pair open: the client's stream and its echo. The client stays connected for a while after the close, to acknowledge it.
subtest "server closes with streams open" => sub {
    my $tempdir = File::Temp::tempdir(CLEANUP => 1);
    my $sock = "$tempdir/h2olog.sock";
    my $server = spawn_h2o(<< "EOT");
webtransport: ON
listen:
  type: unix
  port: $sock
hosts:
  default:
    h2olog: ON
    paths:
      /echo:
        webtransport.echo: ON
EOT
    my ($client_uni, $server_uni) = (6, 15); # 2 is the client's HTTP/3 control stream; 3, 7, 11 are the server's
    # over HTTP/2, the streams of a session are capsules on its CONNECT stream, with no STOP_SENDING or RESET_STREAM of their own
    for my $proto (grep { $_->{name} =~ /^h3/ } @protocols) {
        subtest $proto->{name} => sub {
            my $tracer = H2ologTracer->new({path => $sock});
            my ($out, $status) = run_client($server, $proto, "-w -l 500", "/echo?close=42", "uni-open:hi", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["close 42 \"bye\""], "closed");
            my $find = sub {
                my ($type, $stream_id, @events) = @_;
                my ($at) = grep { $events[$_]{type} =~ $type && $events[$_]{stream_id} == $stream_id } 0 .. $#events;
                $at;
            };
            my ($trace, @events) = ('');
            for (1 .. 50) {
                $trace .= $tracer->get_trace();
                @events = map { JSON::PP::decode_json($_) } grep { /^\{/ } split /\n/, $trace;
                last if defined $find->(qr/^reset_stream(_at)?_send$/, $server_uni, @events);
                sleep 0.1;
            }
            my $events_desc = join "\n", map { "$_->{type} stream=@{[ $_->{stream_id} // '-' ]}" }
                grep { $_->{type} =~ /^(stream_acked|reset_stream(_at)?_send|stop_sending_send)$/ } @events;
            # the acknowledgement that reaches the largest offset of the CONNECT stream (stream 0), i.e., its end
            my ($end, $end_acked_at) = (-1);
            for my $i (0 .. $#events) {
                my $e = $events[$i];
                next unless $e->{type} eq 'stream_acked' && $e->{stream_id} == 0 && $e->{off} + $e->{len} > $end;
                ($end, $end_acked_at) = ($e->{off} + $e->{len}, $i);
            }
            ok defined $end_acked_at, "the end of the session is acknowledged" or return diag $events_desc;
            for ([qr/^stop_sending_send$/, $client_uni, "the client's stream is stopped"],
                 [qr/^reset_stream(_at)?_send$/, $server_uni, "its echo is reset"]) {
                my ($type, $stream_id, $name) = @$_;
                my $at = $find->($type, $stream_id, @events);
                ok defined $at && $at > $end_acked_at, "$name after the end of the session is acknowledged" or diag $events_desc;
            }
        };
    }
};

done_testing;
