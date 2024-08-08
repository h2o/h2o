use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use Protocol::HTTP2::Client;

sub create_client {
    my $port = empty_port();

    my $listening_socket = new IO::Socket::SSL (
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1,
        SSL_cert_file => 'examples/h2o/server.crt',
        SSL_key_file => 'examples/h2o/server.key',
    );
    die "cannot create socket $!\n" unless $listening_socket;
    diag "reverse tunnel client is listening port $port ..";
    my $duration;
    my $serve = sub {
        my ($proto) = @_;
        my $socket = $listening_socket->accept();

        my $data = "";
        my $readlen = $socket->sysread($data, 1 << 24);
        note "client read $readlen bytes:";
        note $data;
        like $data, qr{foo: *FOO}s;
        like $data, qr{bar: *BAR}s;

        my $upgrade_resp = join("\r\n",
            'HTTP/1.1 101 Switching Protocols',
            'Connection: upgrade',
            'Upgrade: reverse',
            "Selected-ALPN: $proto",
            '', '');
        $socket->syswrite($upgrade_resp);

        return $socket;
    };
    return +{ guard => $listening_socket, port => $port, serve => $serve };
};

sub create_server {
    my ($client_port) = @_;
    my $port = 12345; # server's port is just informational, anything is ok
    my $server = spawn_h2o_raw(<<"EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
listen:
    type: reverse
    url: https://127.0.0.1:$client_port/.well-known/reverse/tcp/127.0.0.1/$port
    ssl:
        verify-peer: OFF
    header:
        - "foo: FOO"
        - "bar: BAR"
EOT
    return +{ guard => $server, $port };
}

subtest 'h1' => sub {
    my $client = create_client();
    my $server = create_server($client->{port});

    my $socket = $client->{serve}->('http%2F1.1');
    $socket->syswrite("GET /index.txt HTTP/1.1\r\n\r\n");

    my $resp;
    my $readlen = $socket->sysread($resp, 1 << 24);
    note "server read $readlen bytes:";
    note $resp;
    like $resp, qr{HTTP/[^ ]+ 200\s}is

};

subtest 'h2' => sub {
    plan skip_all => "h2get not found" unless h2get_exists();
    my $client = create_client();
    my $server = create_server($client->{port});

    my $socket = $client->{serve}->('h2');

    my $h2_client = Protocol::HTTP2::Client->new;
    $h2_client->request(
        ':scheme'    => 'https',
        ':authority' => "127.0.0.1:$server->{port}",
        ':method'    => 'GET',
        ':path'      => '/index.txt',
        on_done => sub {
            my ($headers, $data) = @_;
            $headers = +{ @$headers };
            is $headers->{':status'}, 200;
            is $data, "hello\n";
        },
    );
    run_h2_client($h2_client, $socket);
};

sub run_h2_client {
    my ($client, $socket) = @_;
    until ($client->shutdown) {
        # write
        while (my $frame = $client->next_frame) {
            if ($socket->syswrite($frame) != length($frame)) {
                die "failed to write @{[length($frame)]} bytes";
            }
        }
        # read
        my $buf = '';
        while (IO::Select->new($socket)->can_read(0)) {
            my $rlen = $socket->sysread($buf, 4096, length $buf);
            last if $rlen == 0;
            unless (defined $rlen) {
                die "failed to read";
            }
            $client->feed($buf);
        }
    }
}

done_testing;
