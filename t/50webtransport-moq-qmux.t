use strict;
use warnings;
no warnings 'portable';
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

# Tests of the webtransport.moq handler that drive both of its ends: the client speaks WebTransport over HTTP/3 over QMux (h3qx),
# and the relay speaks QMux over cleartext TCP (`qmux-cleartext`). Both are implemented below, as QMux carries QUIC frames in
# records over a byte stream, without packet protection or loss recovery.

use constant {
    WT_STREAM_TYPE_UNI          => 0x54,
    WT_SIGNAL_BIDI              => 0x41,
    WT_CLOSE_SESSION            => 0x2843,
    WT_BUFFERED_STREAM_REJECTED => 0x3994bd84,
    H3_INTERNAL_ERROR           => 0x102,
    H3_ID_ERROR                 => 0x108,
};

sub wt_error_to_http3 { my $code = shift; 0x52e4a40fa8db + $code + int($code / 0x1e) }

sub encode_varint {
    my $v = shift;
    return pack("C", $v) if $v < 0x40;
    return pack("n", 0x4000 | $v) if $v < 0x4000;
    return pack("N", 0x80000000 | $v) if $v < 0x40000000;
    return pack("Q>", 0xc000000000000000 | $v);
}

# decodes a varint from the beginning of the string, removing it; returns undef if incomplete
sub decode_varint {
    my $ref = shift;
    return undef if length $$ref == 0;
    my $first = ord substr $$ref, 0, 1;
    my $len = 1 << ($first >> 6);
    return undef if length $$ref < $len;
    my $v = $first & 0x3f;
    $v = ($v << 8) | ord substr($$ref, $_, 1) for 1 .. $len - 1;
    substr($$ref, 0, $len) = '';
    $v;
}

sub encode_h3_frame { my ($type, $payload) = @_; encode_varint($type) . encode_varint(length $payload) . $payload }

sub encode_close_capsule {
    my ($code, $reason) = @_;
    my $payload = pack("N", $code) . $reason;
    encode_varint(WT_CLOSE_SESSION) . encode_varint(length $payload) . $payload;
}

package QMuxConn {
    use IO::Select;
    use Time::HiRes qw(time);

    sub vi { main::encode_varint(@_) }

    sub new {
        my ($class, $sock, $is_client, %tp) = @_;
        my $self = bless {
            sock       => $sock,
            is_client  => $is_client,
            rbuf       => '',
            streams    => {},    # stream ID => {data, fin, reset, reset_at, stop_sending}
            send_off   => {},
            datagrams  => [],
            close      => undef, # {error, frame_type, reason}
            peer_tp    => undef,
            next_bidi  => $is_client ? 0 : 1,
            next_uni   => $is_client ? 2 : 3,
        }, $class;
        my %params = (4 => 1 << 24, 5 => 1 << 20, 6 => 1 << 20, 7 => 1 << 20, 8 => 100, 9 => 100, %tp);
        my $tps = join '', map {
            my $v = $params{$_};
            vi($_) . (defined $v ? vi(length vi($v)) . vi($v) : vi(0))
        } sort { $a <=> $b } keys %params;
        $self->send("\xff\x51\x53\x30\x0d\x0a\x0d\x0a" . vi(length $tps) . $tps);
        $self;
    }

    sub open_stream {
        my ($self, $uni) = @_;
        my $key = $uni ? 'next_uni' : 'next_bidi';
        my $id = $self->{$key};
        $self->{$key} += 4;
        $id;
    }

    # frames
    sub stream_frame {
        my ($self, $id, $data, $fin) = @_;
        my $off = $self->{send_off}{$id} // 0;
        $self->{send_off}{$id} = $off + length $data;
        vi(0x0e | ($fin ? 1 : 0)) . vi($id) . vi($off) . vi(length $data) . $data;
    }
    sub reset_stream_frame {
        my ($self, $id, $err) = @_;
        vi(0x04) . vi($id) . vi($err) . vi($self->{send_off}{$id} // 0);
    }
    sub stop_sending_frame { my ($self, $id, $err) = @_; vi(0x05) . vi($id) . vi($err) }
    sub datagram_frame { my ($self, $payload) = @_; vi(0x31) . vi(length $payload) . $payload }
    sub close_frame { my ($self, $err, $reason) = @_; vi(0x1d) . vi($err) . vi(length $reason) . $reason }

    # sends the frames in one record
    sub send {
        my ($self, @frames) = @_;
        my $payload = join '', @frames;
        my $rec = pack("n", 0x4000 | length $payload) . $payload;
        while (length $rec) {
            my $n = syswrite $self->{sock}, $rec;
            die "write failed:$!"
                unless defined $n;
            substr($rec, 0, $n) = '';
        }
    }

    sub stream { my ($self, $id) = @_; $self->{streams}{$id} //= {data => '', fin => 0} }

    # reads what is available, then handles the records received
    sub read_input {
        my $self = shift;
        my $n = sysread $self->{sock}, $self->{rbuf}, 65536, length $self->{rbuf};
        if (!$n) {
            $self->{eof} = 1;
            return;
        }
        while (1) {
            my $copy = $self->{rbuf};
            my $len = main::decode_varint(\$copy);
            last unless defined $len && length $copy >= $len;
            my $rec = substr $copy, 0, $len;
            $self->{rbuf} = substr $copy, $len;
            $self->handle_record($rec);
        }
    }

    sub handle_record {
        my ($self, $rec) = @_;
        my $d = sub { main::decode_varint(\$rec) };
        while (length $rec) {
            my $type = $d->();
            if ($type == 0x00 || $type == 0x01) {
                # PADDING, PING
            } elsif (($type & ~7) == 0x08) {
                my $id = $d->();
                my $off = $type & 4 ? $d->() : 0;
                my $len = $type & 2 ? $d->() : length $rec;
                my $data = substr $rec, 0, $len, '';
                my $s = $self->stream($id);
                die "out-of-order STREAM frame" if $off > length $s->{data};
                substr($s->{data}, $off, length($data)) = $data;
                $s->{fin} = 1 if $type & 1;
            } elsif ($type == 0x04) {
                my ($id, $err, $final) = ($d->(), $d->(), $d->());
                $self->stream($id)->{reset} = $err;
            } elsif ($type == 0x24) {
                my ($id, $err, $final, $reliable) = ($d->(), $d->(), $d->(), $d->());
                my $s = $self->stream($id);
                $s->{reset} = $err;
                $s->{reset_at} = $reliable;
            } elsif ($type == 0x05) {
                my ($id, $err) = ($d->(), $d->());
                $self->stream($id)->{stop_sending} = $err;
            } elsif ($type == 0x10 || $type == 0x12 || $type == 0x13 || $type == 0x14 || $type == 0x16 || $type == 0x17) {
                $d->();
            } elsif ($type == 0x11 || $type == 0x15) {
                $d->(); $d->();
            } elsif ($type == 0x30 || $type == 0x31) {
                my $len = $type == 0x31 ? $d->() : length $rec;
                push @{$self->{datagrams}}, substr $rec, 0, $len, '';
            } elsif ($type == 0x1c || $type == 0x1d) {
                my $err = $d->();
                my $frame_type = $type == 0x1c ? $d->() : undef;
                my $len = $d->();
                $self->{close} = {error => $err, frame_type => $frame_type, app => $type == 0x1d, reason => substr $rec, 0, $len, ''};
            } elsif ($type == 0x3f5153300d0a0d0a) {
                my $tps = substr $rec, 0, $d->(), '';
                my %tp;
                while (length $tps) {
                    my $id = main::decode_varint(\$tps);
                    my $v = substr $tps, 0, main::decode_varint(\$tps), '';
                    $tp{$id} = length $v ? main::decode_varint(\$v) : undef;
                }
                $self->{peer_tp} = \%tp;
            } elsif ($type == 0x348c67529ef8c7bd) {
                my $seq = $d->();
                $self->send(vi(0x348c67529ef8c7be) . vi($seq));
            } elsif ($type == 0x348c67529ef8c7be) {
                $d->();
            } else {
                die sprintf "unexpected frame type 0x%x", $type;
            }
        }
    }
}

# reads from the connections until the condition is met; returns if it has been met
sub pump {
    my ($conns, $cond, $timeout) = @_;
    my $deadline = time + ($timeout // 5);
    while (!$cond->()) {
        return 0 if time >= $deadline;
        my @ready = grep { $_->{sock}->can('pending') && $_->{sock}->pending } @$conns;
        @ready = map { my $s = $_; grep { $_->{sock} == $s } @$conns } IO::Select->new(map { $_->{sock} } grep { !$_->{eof} } @$conns)->can_read(0.05)
            unless @ready;
        $_->read_input for @ready;
    }
    1;
}

# parses the HTTP/3 frames of a request stream: returns the status (only those of the static table are understood) and the DATA
sub parse_request_stream {
    my $bytes = shift;
    my ($status, $data) = (undef, '');
    while (length $bytes) {
        my $copy = $bytes;
        my $type = decode_varint(\$copy);
        my $len = decode_varint(\$copy);
        last unless defined $len && length $copy >= $len;
        my $payload = substr $copy, 0, $len;
        $bytes = substr $copy, $len;
        if ($type == 1 && !defined $status) {
            my %statuses = (24 => 103, 25 => 200, 26 => 304, 27 => 404, 28 => 503, 63 => 100, 64 => 204, 65 => 206, 66 => 302, 67 => 400,
                            68 => 403, 69 => 421, 70 => 425, 71 => 500);
            my $first = ord substr $payload, 2, 1;
            $status = ($first & 0xc0) == 0xc0 ? $statuses{$first & 0x3f} // "static:" . ($first & 0x3f) : "literal";
        } elsif ($type == 0) {
            $data .= $payload;
        }
    }
    ($status, $data);
}

# decodes the CLOSE_WEBTRANSPORT_SESSION capsule; returns (code, reason) or an empty list
sub decode_close_capsule {
    my $bytes = shift;
    my $type = decode_varint(\$bytes);
    my $len = decode_varint(\$bytes);
    return () unless defined $len && $type == WT_CLOSE_SESSION && length $bytes >= $len;
    (unpack("N", $bytes), substr $bytes, 4, $len - 4);
}

my $relay_listener = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    LocalPort => 0,
    Proto     => 'tcp',
    Listen    => 5,
    ReuseAddr => 1,
) or die "failed to listen:$!";
my $relay_port = $relay_listener->sockport;
my $h3qx_port = empty_port();

my $server = spawn_h2o(<< "EOT");
webtransport: ON
listen:
  port: $h3qx_port
  h3qx: ON
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /moq:
        webtransport.moq:
          url: moqt://127.0.0.1:$relay_port
          qmux-cleartext: ON
EOT

# Opens a session: connects as the client, sends the extended CONNECT on `$session_id`, accepts the connection from h2o as the
# relay, and waits for the 2xx. Returns the client, the relay, and the stream of the session.
sub open_session {
    my (%opts) = @_;
    my $session_id = $opts{session_id} // 0;

    my $sock = IO::Socket::SSL->new(
        PeerAddr           => "127.0.0.1:$h3qx_port",
        SSL_alpn_protocols => ["h3qx-01"],
        SSL_verify_mode    => SSL_VERIFY_NONE,
    ) or die "failed to connect:$SSL_ERROR";
    die "unexpected ALPN" unless ($sock->alpn_selected // '') eq 'h3qx-01';
    my $client = QMuxConn->new($sock, 1, 0x20 => 1500, %{$opts{client_tp} // {}});

    # the control stream carrying SETTINGS_ENABLE_WEBTRANSPORT and SETTINGS_H3_DATAGRAM
    my $settings = encode_varint(0x2b603742) . encode_varint(1) . encode_varint(0x33) . encode_varint(1);
    my $ctrl = $client->open_stream(1);
    $client->{next_bidi} = $session_id + 4;
    # the extended CONNECT; QPACK without the dynamic table and Huffman encoding
    my $qstr = sub { my $s = shift; die if length $s >= 127; pack("C", length $s) . $s };
    my $lit = sub { my ($n, $v) = @_; die if length($n) - 7 >= 127; pack("CC", 0x27, length($n) - 7) . $n . $qstr->($v) };
    my $headers = "\0\0" . "\xcf" . "\xd7" . "\x50" . $qstr->("127.0.0.1") . "\x51" . $qstr->("/moq")
        . $lit->(":protocol", "webtransport") . $lit->("sec-webtransport-http3-draft02", "1")
        . $lit->("wt-available-protocols", '"moqt-22"');
    $client->send($client->stream_frame($ctrl, encode_varint(0) . encode_h3_frame(4, $settings)),
        $client->stream_frame($session_id, encode_h3_frame(1, $headers)));

    # accept the connection as the relay
    IO::Select->new($relay_listener)->can_read(5)
        or die "h2o did not connect to the relay";
    my $relay = QMuxConn->new(scalar $relay_listener->accept, 0, %{$opts{relay_tp} // {}});

    pump([$client, $relay], sub { defined((parse_request_stream($client->stream($session_id)->{data}))[0]) })
        or die "no response";
    my ($status) = parse_request_stream($client->stream($session_id)->{data});
    is $status, 200, "status";
    pump([$client, $relay], sub { $relay->{peer_tp} && $client->{peer_tp} });

    ($client, $relay, $session_id);
}

subtest 'streams' => sub {
    my ($client, $relay, $session_id) = open_session();
    my $wt_uni = encode_varint(WT_STREAM_TYPE_UNI) . encode_varint($session_id);
    my $wt_bidi = encode_varint(WT_SIGNAL_BIDI) . encode_varint($session_id);

    # client to relay, unidirectional
    my $cu = $client->open_stream(1);
    $client->send($client->stream_frame($cu, $wt_uni . "hello", 1));
    ok pump([$client, $relay], sub { $relay->stream(2)->{fin} }), "uni stream reached the relay";
    is $relay->stream(2)->{data}, "hello", "uni stream payload, without the WebTransport header";

    # relay to client, unidirectional
    my $ru = $relay->open_stream(1);
    $relay->send($relay->stream_frame($ru, "world", 1));
    my $cid;
    ok pump([$client, $relay], sub { ($cid) = grep { $_ % 4 == 3 && $client->stream($_)->{fin} } keys %{$client->{streams}}; defined $cid }),
        "uni stream reached the client";
    is $client->stream($cid)->{data}, $wt_uni . "world", "uni stream payload, with the WebTransport header";

    # client to relay and back, bidirectional
    my $cb = $client->open_stream(0);
    $client->send($client->stream_frame($cb, $wt_bidi . "ping", 1));
    ok pump([$client, $relay], sub { $relay->stream(0)->{fin} }), "bidi stream reached the relay";
    is $relay->stream(0)->{data}, "ping", "bidi request";
    $relay->send($relay->stream_frame(0, "pong", 1));
    ok pump([$client, $relay], sub { $client->stream($cb)->{fin} }), "bidi response reached the client";
    is $client->stream($cb)->{data}, "pong", "bidi response";

    # relay to client, bidirectional
    my $rb = $relay->open_stream(0);
    $relay->send($relay->stream_frame($rb, "from-relay", 1));
    ok pump([$client, $relay], sub { ($cid) = grep { $_ % 4 == 1 && $client->stream($_)->{fin} } keys %{$client->{streams}}; defined $cid }),
        "bidi stream reached the client";
    is $client->stream($cid)->{data}, $wt_bidi . "from-relay", "bidi stream payload, with the WebTransport signal";
};

subtest 'datagrams' => sub {
    # the session is on stream 4, so that the Quarter Stream ID (1) differs from the stream ID
    my ($client, $relay, $session_id) = open_session(session_id => 4, relay_tp => {0x20 => 100});
    is $relay->{peer_tp}{0x20}, 1500, "h2o advertises max_datagram_frame_size to the relay";

    $client->send($client->datagram_frame(encode_varint(1) . "x" x 200), $client->datagram_frame(encode_varint(1) . "up"));
    ok pump([$client, $relay], sub { @{$relay->{datagrams}} != 0 }), "datagram reached the relay";
    is_deeply $relay->{datagrams}, ["up"], "Quarter Stream ID removed; datagram too large for the relay dropped";

    $relay->send($relay->datagram_frame("down"));
    ok pump([$client, $relay], sub { @{$client->{datagrams}} != 0 }), "datagram reached the client";
    is_deeply $client->{datagrams}, [encode_varint(1) . "down"], "Quarter Stream ID prepended";

    # datagrams of other flows are not forwarded
    $client->send($client->datagram_frame(encode_varint(0) . "other"), $client->datagram_frame(encode_varint(1) . "again"));
    ok pump([$client, $relay], sub { @{$relay->{datagrams}} == 2 });
    is $relay->{datagrams}[1], "again", "datagram of another flow dropped";
};

subtest 'resets' => sub {
    my ($client, $relay, $session_id) = open_session(client_tp => {0x1d => undef});
    my $wt_uni = encode_varint(WT_STREAM_TYPE_UNI) . encode_varint($session_id);

    # a stream reset by the relay before the header is sent to the client is reset with RESET_STREAM_AT, covering the header
    my $ru = $relay->open_stream(1);
    $relay->send($relay->stream_frame($ru, "abc"), $relay->reset_stream_frame($ru, 5));
    my $cid;
    ok pump([$client, $relay], sub { ($cid) = grep { $_ % 4 == 3 && defined $client->stream($_)->{reset} } keys %{$client->{streams}}; defined $cid }),
        "reset reached the client";
    is $client->stream($cid)->{reset}, wt_error_to_http3(5), "error code mapped";
    is $client->stream($cid)->{reset_at}, length $wt_uni, "RESET_STREAM_AT covering the header";
    is substr($client->stream($cid)->{data}, 0, length $wt_uni), $wt_uni, "header received";

    # a reset by the client is passed to the relay with the error code unmapped
    my $cu = $client->open_stream(1);
    $client->send($client->stream_frame($cu, $wt_uni . "def"));
    ok pump([$client, $relay], sub { $relay->stream(2)->{data} eq "def" }), "stream reached the relay";
    $client->send($client->reset_stream_frame($cu, wt_error_to_http3(7)));
    ok pump([$client, $relay], sub { defined $relay->stream(2)->{reset} }), "reset reached the relay";
    is $relay->stream(2)->{reset}, 7, "error code unmapped";

    # STOP_SENDING by the relay stops the client's stream
    my $cu2 = $client->open_stream(1);
    $client->send($client->stream_frame($cu2, $wt_uni . "ghi"));
    ok pump([$client, $relay], sub { $relay->stream(6)->{data} eq "ghi" }), "stream reached the relay";
    $relay->send($relay->stop_sending_frame(6, 9));
    ok pump([$client, $relay], sub { defined $client->stream($cu2)->{stop_sending} }), "STOP_SENDING reached the client";
    is $client->stream($cu2)->{stop_sending}, wt_error_to_http3(9), "error code mapped";
};

subtest 'stream rejected' => sub {
    my ($client, $relay, $session_id) = open_session();
    # a stream of another session
    my $cu = $client->open_stream(1);
    $client->send($client->stream_frame($cu, encode_varint(WT_STREAM_TYPE_UNI) . encode_varint($session_id + 4) . "x"));
    ok pump([$client, $relay], sub { defined $client->stream($cu)->{stop_sending} }), "stopped";
    is $client->stream($cu)->{stop_sending}, WT_BUFFERED_STREAM_REJECTED, "with H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED";
};

subtest 'invalid session ID' => sub {
    my ($client, $relay, $session_id) = open_session();
    my $cu = $client->open_stream(1);
    $client->send($client->stream_frame($cu, encode_varint(WT_STREAM_TYPE_UNI) . encode_varint(2) . "x"));
    ok pump([$client, $relay], sub { $client->{close} }), "connection closed";
    is $client->{close}{error}, H3_ID_ERROR, "with H3_ID_ERROR";
};

subtest 'client closes the session' => sub {
    my ($client, $relay, $session_id) = open_session();
    $client->send($client->stream_frame($session_id, encode_h3_frame(0, encode_close_capsule(7, "bye"))));
    ok pump([$client, $relay], sub { $relay->{close} }), "relay connection closed";
    is $relay->{close}{error}, 7, "with the application error code";
    is $relay->{close}{reason}, "bye", "with the reason";
    ok pump([$client, $relay], sub { $client->stream($session_id)->{fin} }), "response ended";
    # the request stream is stopped as that of an early response (the error code being H2O_HTTP3_ERROR_EARLY_RESPONSE)
    ok pump([$client, $relay], sub { defined $client->stream($session_id)->{stop_sending} }), "request stream stopped";
};

subtest 'data after CLOSE_WEBTRANSPORT_SESSION' => sub {
    my ($client, $relay, $session_id) = open_session();
    $client->send($client->stream_frame($session_id, encode_h3_frame(0, encode_close_capsule(7, "bye") . "junk")));
    ok pump([$client, $relay], sub { defined $client->stream($session_id)->{reset} }), "request stream reset";
    is $client->stream($session_id)->{reset}, H3_INTERNAL_ERROR, "with H3_INTERNAL_ERROR (see the note in the handler)";
    ok pump([$client, $relay], sub { $relay->{close} }), "relay connection closed";
    is $relay->{close}{error}, 7, "with the application error code";
};

subtest 'relay closes the session' => sub {
    my ($client, $relay, $session_id) = open_session();
    $relay->send($relay->close_frame(9, "x" x 1000 . "\x{e3}\x{81}\x{82}" x 10));
    ok pump([$client, $relay], sub { $client->stream($session_id)->{fin} }), "response ended";
    my (undef, $data) = parse_request_stream($client->stream($session_id)->{data});
    my ($code, $reason) = decode_close_capsule($data);
    is $code, 9, "CLOSE_WEBTRANSPORT_SESSION with the application error code";
    is length $reason, 1000 + 3 * 8, "reason limited to 1024 bytes, at a character boundary";
};

subtest 'relay gone' => sub {
    my ($client, $relay, $session_id) = open_session();
    my $wt_uni = encode_varint(WT_STREAM_TYPE_UNI) . encode_varint($session_id);
    my $cu = $client->open_stream(1);
    $client->send($client->stream_frame($cu, $wt_uni . "abc"));
    ok pump([$client, $relay], sub { $relay->stream(2)->{data} eq "abc" }), "stream reached the relay";
    close $relay->{sock};
    ok pump([$client], sub { $client->stream($session_id)->{fin} }), "response ended";
    ok defined $client->stream($cu)->{stop_sending}, "client stream stopped";
};

done_testing;
