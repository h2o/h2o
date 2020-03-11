use strict;
use warnings;
use IO::Socket::INET;
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;
use Net::EmptyPort qw(check_port empty_port);
use File::Temp qw(tempfile);

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

my $server = spawn_h2o(<< "EOT");
http1-request-io-timeout: 2
http1-request-timeout: 5
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.ssl.verify-peer: OFF
        proxy.timeout.io: 1000000
EOT

my $port = $server->{port};
sub build_test {
    my $times = shift;
    my $sleep = shift;
    my $t = "";
    foreach (1 .. $times) {
        $t = $t."\n".'$writer->write("lorem ipsum dolor sit amet");';
        $t = $t."\n".'sleep '.$sleep.";\n";
    }
    my $prefix = 'return sub {
        my $responder = shift;
        my $writer = $responder->([ 200, [ "content-type" => "text/plain" ] ]);';
   my $suffix = '
        $writer->close;
};';
    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    print $conffh $prefix.$t.$suffix;
    close($conffh);
    return $conffn;
}

my $conffn = build_test(1, 3);
my $res = `curl -X POST -d \@$conffn -svo /dev/null http://127.0.0.1:$port/custom-perl 2>&1 > /dev/null`;
like $res, qr{transfer closed with outstanding read data remaining}, "connection was closed";

$conffn = build_test(8, 1);
$res = `curl -X POST -d \@$conffn -svo /dev/null http://127.0.0.1:$port/custom-perl 2>&1 > /dev/null`;
like $res, qr{Connection.*to host 127.0.0.1 left intact}, "connection was closed";

done_testing();
