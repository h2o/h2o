use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use IPC::Open3;
use Test::More;
use Time::HiRes qw(sleep time);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

for my $proto (
    ["h1", "http",  ""],
    ["h2", "https", "-2 100"],
    ["h3", "https", "-3 100"],
) {
    my ($name, $scheme, $opts) = @$proto;
    subtest $name => sub {
        my ($origin_pid, $origin_port, $req_file, $start_origin_tls) = spawn_delayed_tls_origin();

        my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: https://127.0.0.1:$origin_port
        proxy.timeout.io: 30000
EOT

        my $port = $name eq "h1" ? $server->{port} : $name eq "h2" ? $server->{tls_port} : $server->{quic_port};
        my ($client_stdin, $client_stdout);
        my $client_pid = open3(
            $client_stdin,
            $client_stdout,
            undef,
            "exec $client_prog -k $opts -m POST --input /dev/stdin $scheme://127.0.0.1:$port/ 2>&1"
        );
        die "failed to spawn h2o-httpclient"
            unless $client_pid > 0;

        is syswrite($client_stdin, "hello"), 5, "sent request body";
        sleep 1;

        my $start = time;
        close $client_stdin;
        sleep 1;
        $start_origin_tls->();

        for (my $i = 0; $i != 20 && !-e $req_file; ++$i) {
            sleep 0.25;
        }
        ok -e $req_file, "origin recorded the request";
        cmp_ok time - $start, "<", 3, "FIN was delivered before idle timeout";

        if (-e $req_file) {
            open my $fh, "<", $req_file
                or die "failed to open $req_file:$!";
            my $req = do { local $/; <$fh> };
            my ($headers, $body) = split /\r\n\r\n/, $req, 2;
            like $headers, qr{^POST / HTTP/1\.1\r\n}s, "received POST";

            my ($decoded, $complete) = decode_request_body($headers, $body // "");
            is $decoded, "hello", "received request body";
            ok $complete, "received complete request body";
        }

        my $resp = read_until_eof($client_stdout, 5);
        my ($resp_headers, $resp_body) = split /\n\n/, $resp, 2;
        like $resp_headers, qr{^HTTP/\S+ 200[^\n]*\n}s, "client received response headers";
        is $resp_body, "ok", "client received response body";

        kill 'KILL', $client_pid;
        waitpid $client_pid, 0;
        kill 'KILL', $origin_pid;
        waitpid $origin_pid, 0;
    };
}

done_testing;

sub spawn_delayed_tls_origin {
    my $listener = IO::Socket::INET->new(
        Listen    => 1,
        LocalAddr => "127.0.0.1:0",
        Proto     => "tcp",
    ) or die "failed to open listener:$!";
    my $origin_port = $listener->sockport;
    my $req_file = "$tempdir/origin-$origin_port.txt";
    pipe my $start_r, my $start_w
        or die "pipe failed:$!";
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        close $start_w;
        my $sock = $listener->accept
            or die "accept failed:$!";
        sysread $start_r, my $dummy, 1;
        $sock = IO::Socket::SSL->start_SSL(
            $sock,
            SSL_server    => 1,
            SSL_cert_file => "examples/h2o/server.crt",
            SSL_key_file  => "examples/h2o/server.key",
        ) or die "TLS handshake failed:" . IO::Socket::SSL::errstr();
        my $select = IO::Select->new($sock);
        my $req = "";
        my $deadline = time + 5;
        while (time < $deadline) {
            last if request_is_complete($req);
            my $timeout = $deadline - time;
            $timeout = 0.25 if $timeout > 0.25;
            if ($select->can_read($timeout)) {
                my $r = sysread $sock, my $buf, 8192;
                die "read failed:$!"
                    unless defined $r;
                last if $r == 0;
                $req .= $buf;
            }
        }
        open my $fh, ">", $req_file
            or die "failed to open request file:$!";
        print $fh $req;
        close $fh;
        print $sock "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
        exit 0;
    }
    close $start_r;
    undef $listener;
    return ($pid, $origin_port, $req_file, sub {
        syswrite $start_w, "x";
        close $start_w;
    });
}

sub request_is_complete {
    my $req = shift;
    return 0
        unless $req =~ /\r\n\r\n/s;
    my ($headers, $body) = split /\r\n\r\n/, $req, 2;
    return $req =~ /\r\n0\r\n\r\n/s
        if $headers =~ /^transfer-encoding: chunked\r\n/mi;
    return length($body) >= $1
        if $headers =~ /^content-length: ([0-9]+)\r\n/mi;
    return 1;
}

sub decode_chunked {
    my $src = shift;
    my $decoded = "";
    while (1) {
        return ($decoded, 0)
            unless $src =~ s/^([0-9a-fA-F]+)[^\r\n]*\r\n//;
        my $len = hex $1;
        return ($decoded, 1)
            if $len == 0 && $src =~ /^\r\n/;
        return ($decoded, 0)
            if length($src) < $len + 2;
        return ($decoded, 0)
            unless substr($src, $len, 2) eq "\r\n";
        $decoded .= substr($src, 0, $len);
        substr($src, 0, $len + 2) = "";
    }
}

sub decode_request_body {
    my ($headers, $body) = @_;
    return decode_chunked($body)
        if $headers =~ /^transfer-encoding: chunked\r\n/mi;
    return (substr($body, 0, $1), length($body) >= $1)
        if $headers =~ /^content-length: ([0-9]+)\r\n/mi;
    return ($body, 1);
}

sub read_until_eof {
    my ($fh, $timeout) = @_;
    my $select = IO::Select->new($fh);
    my $buf = "";
    my $deadline = time + $timeout;
    while (time < $deadline) {
        my $wait = $deadline - time;
        $wait = 0.25 if $wait > 0.25;
        last unless $select->can_read($wait);
        my $r = sysread $fh, my $chunk, 8192;
        last unless defined $r && $r > 0;
        $buf .= $chunk;
    }
    return $buf;
}
