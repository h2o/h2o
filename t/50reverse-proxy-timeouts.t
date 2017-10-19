use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use File::Temp qw(tempfile);
use Socket;


plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $silent_port = empty_port({ host => '0.0.0.0' });

socket(my $silent_server, PF_INET, SOCK_STREAM, getprotobyname("tcp")) || die "socket: $!";
setsockopt($silent_server, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
bind($silent_server, sockaddr_in($silent_port, INADDR_ANY)) || die "bind: $!";
listen($silent_server, SOMAXCONN) || die "listen: $!";

my $upstream_port = empty_port({ host => '0.0.0.0' });
my $upstream = spawn_server(
    argv => [
        qw(
            plackup -s Standalone --ssl=1 --ssl-key-file=examples/h2o/server.key --ssl-cert-file=examples/h2o/server.crt --port
        ),
        $upstream_port, ASSETS_DIR . "/upstream.psgi"
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

sub doit {
    my $uport = shift;
    my $io = shift;
    my $connect = shift;
    my $first_byte = shift;
    my $failure = shift;
    my $success = shift;
    my $fail_with_chunks = shift;

    diag("io: $io, connect: $connect, first_byte: $first_byte");
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$uport
        proxy.ssl.verify-peer: OFF
        @{[ $io == 0 ? "" : "proxy.timeout.io: $io" ]}
        @{[ $connect == 0 ? "" : "proxy.timeout.connect: $connect" ]}
        @{[ $first_byte == 0 ? "" : "proxy.timeout.first_byte: $first_byte" ]}
EOT
    for my $t ($failure, $success) {
        if ($success eq "") {
            next;
        }
        my ($conffh, $conffn) = tempfile(UNLINK => 1);
        print $conffh $t;
        close($conffh);
        my $port = $server->{port};
        my $res = `curl -X POST -d \@$conffn -svo /dev/null http://127.0.0.1:$port/custom-perl 2>&1 > /dev/null`;
        if ($t eq $failure) {
            if ($fail_with_chunks) {
                like $res, qr{Illegal or missing hexadecimal sequence in chunked-encoding}, "Truncated transfer";
            } else {
                like $res, qr{HTTP/1\.1 502 }, "502 response on failure";
            }
        } else {
            like $res, qr{HTTP/1\.1 200 }, "200 response on success";
        }
    }
};

doit($upstream_port, 2000, 0, 0,
     "sleep 3; return [ 200, [], ['ok']];",
     "sleep 1; return [ 200, [], ['ok']];", 0);
doit($upstream_port, 2000, 30000, 0,
     "sleep 3; return [ 200, [], ['ok']];",
     "sleep 1; return [ 200, [], ['ok']];", 0);
doit($silent_port, 0, 2000, 0,
     "sleep 3; return [ 200, [], ['ok']];", "", 0);
doit($upstream_port, 2000, 30000, 30000,
    'return sub {
        my $responder = shift;
        my $writer = $responder->([ 200, [ "content-type" => "text/plain" ] ]);
        $writer->write("lorem ipsum dolor sit amet");
        sleep 3;
        $writer->write("lorem ipsum dolor sit amet");
        $writer->close;
    };',
    'return sub {
        my $responder = shift;
        my $writer = $responder->([ 200, [ "content-type" => "text/plain" ] ]);
        $writer->write("lorem ipsum dolor sit amet");
        sleep 1;
        $writer->write("lorem ipsum dolor sit amet");
        $writer->close;
    };', 1);


done_testing();
