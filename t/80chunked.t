use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

# determine upstream port to be used, spawn h2o that would connect there
my $upstream_port = empty_port();
my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

# spawn upstream psgi, check if it can receive the chunked request and a requset that follows it being forwarded by h2o
subtest "psgi-echo" => sub {
    plan skip_all => 'Starlet not found'
        unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
    # spawn server
    my $upstream = spawn_server(
        argv     => [qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", "t/assets/upstream.psgi"],
        is_ready => sub {
            check_port($upstream_port);
        },
    );
    # send 2 requests
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server->{port}",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    my $msg = <<"EOT";
POST /echo HTTP/1.1\r
Transfer-Encoding: chunked\r
\r
5\r
abcde\r
EOT
    syswrite($sock, $msg) == length($msg)
        or die "failed to send data:$!";
    sleep 1;
    $msg = <<"EOT";
0\r
\r
GET / HTTP/1.0\r
\r
EOT
    syswrite($sock, $msg) == length($msg)
        or die "failed to send data:$!";
    # read and check response
    my $resp = read_all($sock);
    like $resp, qr{^HTTP/1\.1 200 OK\r\n.*?\r\n\r\nabcdeHTTP/1\.1 404 Not Found\r\n}s;
};

subtest "slow" => sub {
    plan skip_all => "printf not found"
        unless prog_exists("printf");
    plan skip_all => "nc not found"
        unless prog_exists("nc");

    # setup upstream that records all the input
    open my $dummyfh, "|-", "exec nc -l 127.0.0.1 $upstream_port > $tempdir/req.txt"
        or die "failed to launch nc:$!";
    sleep 1;

    # connect and send request, sending one byte every 100ms
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server->{port}",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    my $req = "POST / HTTP/1.1\r\nTransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
    for (0 .. length($req) - 1) {
        syswrite($sock, substr($req, $_, 1)) == 1
            or die "failed to send data:$!";
        sleep 0.1;
    }
    sleep 1;

    # fetch all recorded input
    $req = do {
        open my $fh, "$tempdir/req.txt"
            or die "failed to open $tempdir/req.txt:$!";
        local $/;
        <$fh>;
    };
    my ($req_headers, $req_body_chunked) = split /\r\n\r\n/s, $req, 2;
    like $req_headers, qr{^POST / HTTP\/1\.1\r\n}s;
    my $req_body = parse_chunked($req_body_chunked);
    is $req_body, 'helloworld';
};

done_testing;

sub read_all {
    my $sock = shift;
    my $resp = '';
    while (sysread($sock, $resp, 65536, length($resp))) {}
    $resp;
}

sub parse_chunked {
    my $orig_input = shift;
    my ($input, $output) = ($orig_input, '');
    while (1) {
        if ($input !~ /^([0-9]+)\r\n/s) {
            fail("parse_chunked");
            diag("invalid chunk length:$input");
            last;
        }
        my $chunk_len = $1;
        $input = $';
        if (length($input) < $chunk_len) {
            fail("parse_chunked");
            diag("partial input:$input");
            last;
        }
        $output .= substr $input, 0, $chunk_len;
        $input = substr $input, $chunk_len;
        if ($input !~ /^\r\n/s) {
            fail("parse_chunked");
            diag("chunk does not end with CRLF:$input");
            last;
        }
        $input = $';
        if ($chunk_len == 0) {
            if (length $input == 0) {
                pass "parse_chunked";
            } else {
                fail("parse_chunked");
                diag("excess data at tail:$input");
            }
            last;
        }
    }
    return $output;
}
