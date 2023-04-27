use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use Time::HiRes qw(sleep);
use IO::Socket::INET;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $logfile = "$tempdir/access.log";
my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 10
hosts:
  default:
    paths:
      "/":
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
access-log:
  path: $logfile
  format: "@{[ join("\\t", map { "proxy.request-bytes$_:%{proxy.request-bytes$_}x" } ('', '-header', '-body')) ]}"
EOT

sub doit {
    my ($streaming) = @_;
    my $expected_body_size = $streaming ? 25 : 10;
    my $expected_header_size = $streaming ? 174 : 166;

    my $req = join("\r\n", (
        'POST /index.txt HTTP/1.1',
        ($streaming ? 'Transfer-Encoding: chunked' : "Content-Length: $expected_body_size"),
        '', ''
    ));
    my $conn = IO::Socket::INET->new(
        PeerHost => q(127.0.0.1),
        PeerPort => $server->{port},
        Proto    => q(tcp),
    ) or die "failed to connect to host:$!";
    $conn->syswrite($req);

    if ($streaming) {
        $conn->syswrite("5\r\naaaaa\r\n");
        sleep 0.1;
        $conn->syswrite("5\r\nbbbbb\r\n0\r\n\r\n");
    } else {
        $conn->syswrite('aaaaabbbbb');
    }
    $conn->sysread(my $buf, 4096);
    like $buf, qr{^HTTP/1.1 200}is;
    $conn->close or die "$1";
    sleep 0.1;

    my @log = do {
        open my $fh, "<", $logfile
            or die "failed to open $logfile: $!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };
    my $log = pop(@log);
    my %map = map { split(':', $_) } split("\t", $log);
    is $map{'proxy.request-bytes-body'}, $expected_body_size, 'body';
    is $map{'proxy.request-bytes-header'}, $expected_header_size, 'header';
    is $map{'proxy.request-bytes'}, $expected_body_size + $expected_header_size, 'total';
}

subtest 'non-streaming' => sub {
    doit(0);
};

subtest 'streaming' => sub {
    doit(1);
};

done_testing();

