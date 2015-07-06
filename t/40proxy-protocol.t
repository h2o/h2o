use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use IO::Socket::SSL;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $port = empty_port();

sub spawn_h2o {
    my ($proxy_protocol, $ssl) = @_;

    open my $fh, ">", "$tempdir/h2o.conf"
        or die "failed to create file:$tempdir/h2o.conf:$!";
    print $fh <<"EOT";
handshake-timeout: 3
hosts:
  default:
    access-log:
      format: "%h"
      path: $tempdir/access_log
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
    listen:
      host: 127.0.0.1
      port: $port
      proxy-protocol: @{[$proxy_protocol ?  "ON" : "OFF"]}
EOT
    if ($ssl) {
        print $fh <<"EOT";
      ssl:
        key-file: examples/h2o/server.key
        certificate-file: examples/h2o/server.crt
EOT
    }
    close $fh;

    spawn_server(
        argv     => [ bindir() . "/h2o", "-c", "$tempdir/h2o.conf" ],
        is_ready => sub {
            check_port($port);
        },
    );
}

sub fetch {
    my $req = shift;
    my $conn = IO::Socket::INET->new(
        PeerHost => q(127.0.0.1),
        PeerPort => $port,
        Proto    => q(tcp),
    ) or die "failed to connect to host:$!";
    $conn->write($req);
    $conn->read(my $buf, 1048576);
    $buf;
}

sub fetch_ssl {
    my ($pre, $req) = @_;
    my $conn = IO::Socket::INET->new(
        PeerHost           => q(127.0.0.1),
        PeerPort           => $port,
        SSL_startHandshake => 0,
    ) or die "failed to connect to host:$!";
    $conn->write($pre);
    IO::Socket::SSL->start_SSL($conn, SSL_verify_mode => 0)
        or die $SSL_ERROR;
    $conn->write($req);
    $conn->read(my $buf, 1048576);
    $buf;
}

sub last_log {
    open my $fh, "<", "$tempdir/access_log"
        or die "failed to open file:$tempdir/access_log:$!";
    my $last;
    while (<$fh>) {
        $last = $_;
    }
    chomp $last;
    $last;
}

sub test_timeout {
    local $@;
    my $gotsig = 0;
    local $SIG{ALRM} = sub {
        $gotsig = 1;
        die "gotsig";
    };
    alarm(5);
    eval { fetch("") };
    alarm(0);
    ok ! $gotsig;
}

subtest "http" => sub {
    my $guard = spawn_h2o(1, 0);
    subtest "with proxy" => sub {
        my $resp = fetch("PROXY TCP4 1.2.3.4 5.6.7.8 1234 9999\r\nGET / HTTP/1.0\r\n\r\n");
        like $resp, qr{^HTTP/1.1 200 OK\r\n}s;
        is last_log(), "1.2.3.4";
    };
    subtest "without proxy" => sub {
        my $resp = fetch("GET / HTTP/1.0\r\n\r\n");
        like $resp, qr{^HTTP/1.1 200 OK\r\n}s;
        is last_log(), "127.0.0.1";
    };
    subtest "timeout" => sub {
        test_timeout();
    };
};

subtest "https" => sub {
    my $guard = spawn_h2o(1, 1);
    subtest "with proxy" => sub {
        my $resp = fetch_ssl("PROXY TCP4 1.2.3.4 5.6.7.8 1234 9999\r\n", "GET / HTTP/1.0\r\n\r\n");
        like $resp, qr{^HTTP/1.1 200 OK\r\n}s;
        is last_log(), "1.2.3.4";
    };
    subtest "without proxy" => sub {
        my $resp = fetch_ssl("", "GET / HTTP/1.0\r\n\r\n");
        like $resp, qr{^HTTP/1.1 200 OK\r\n}s;
        is last_log(), "127.0.0.1";
    };
    subtest "timeout" => sub {
        test_timeout();
    };
};

subtest "off" => sub {
    my $guard = spawn_h2o(0, 0);
    subtest "with proxy" => sub {
        my $resp = fetch("PROXY TCP4 1.2.3.4 5.6.7.8 1234 9999\r\nGET / HTTP/1.0\r\n\r\n");
        unlike $resp, qr{^HTTP/1.1 200 OK\r\n}s;
    };
    subtest "without proxy" => sub {
        my $resp = fetch("GET / HTTP/1.0\r\n\r\n");
        like $resp, qr{^HTTP/1.1 200 OK\r\n}s;
    };
};

subtest "https handshake timeout" => sub {
    # timeout test for PROXY:OFF over HTTPS is implemented here since it is easier to do so
    my $guard = spawn_h2o(0, 1);
    test_timeout();
};

done_testing;
