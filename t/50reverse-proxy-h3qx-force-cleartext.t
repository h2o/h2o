use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

# accepts one connection and returns the first bytes sent by h2o
sub first_bytes_sent_to_backend {
    my $conf = shift;
    my $upstream_port = empty_port();
    my $listen = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto     => 'tcp',
        Listen    => 1,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$upstream_port:$!";
    my $backend = spawn_forked(sub {
        my $sock = $listen->accept
            or die "accept failed:$!";
        my $buf = '';
        my $sel = IO::Select->new($sock);
        while (length($buf) < 10 && $sel->can_read(5)) {
            last unless sysread($sock, $buf, 4096, length $buf);
        }
        print $buf;
    });
    close $listen;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
$conf
EOT
    `curl --silent --max-time 3 http://127.0.0.1:$server->{port}/ 2>&1`;
    my ($out) = $backend->{wait}->();
    $out;
}

subtest 'ON' => sub {
    my $out = first_bytes_sent_to_backend(<< 'EOT');
        proxy.h3qx.ratio: 100
        proxy.h3qx.force-cleartext: ON
EOT
    ok length($out) >= 10, 'received a record';
    # QMux record header (2 bytes) followed by the QX_TRANSPORT_PARAMETERS frame type
    is substr($out, 2, 8), "\xffQS0\r\n\r\n", 'QMux transport parameters are sent without TLS';
};

subtest 'OFF' => sub {
    my $out = first_bytes_sent_to_backend(<< 'EOT');
        proxy.h3qx.ratio: 100
EOT
    like $out, qr{^GET / HTTP/1\.1\r\n}, 'falls back to HTTP/1.1 on cleartext';
};

subtest 'config errors' => sub {
    my $test_conf = sub {
        my $conf = shift;
        open my $fh, '>', "$tempdir/h2o.conf"
            or die "failed to create file:$!";
        print {$fh} <<"EOT";
listen: @{[empty_port()]}
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:1/
$conf
EOT
        close $fh;
        my $out = `@{[bindir]}/h2o -t -c $tempdir/h2o.conf 2>&1`;
        ($?, $out);
    };
    my ($status, $out) = $test_conf->(<< 'EOT');
        proxy.h3qx.force-cleartext: ON
EOT
    isnt $status, 0, 'ratio not 100';
    like $out, qr{`proxy\.h3qx\.ratio` must be set to `100`};
    ($status, $out) = $test_conf->(<< 'EOT');
        proxy.h3qx.ratio: 100
        proxy.h3qx.force-cleartext: ON
        proxy.http2.ratio: 100
        proxy.http2.force-cleartext: ON
EOT
    isnt $status, 0, 'both force-cleartext';
    like $out, qr{cannot be both `ON`};
};

done_testing;
