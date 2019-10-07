use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port wait_port);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

run_as_root();

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

plan skip_all => 'dtrace not found'
    unless prog_exists('dtrace');
plan skip_all => 'bpftrace is not supported'
    if $^O eq 'linux';
plan skip_all => 'unbuffer not found'
    unless prog_exists('unbuffer');

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

subtest 'retry' => sub {
    my $doit = sub {
        my $on = shift;
        my $guard = spawn_h2o(<< "EOT");
listen:
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  quic:
    retry: $on
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
        wait_port({port => $quic_port, proto => 'udp'});
        $guard;
    };
    subtest 'off' => sub {
        my $guard = $doit->('OFF');
    };
    subtest 'on' => sub {
        my $guard = $doit->('OFF');
    };
};

done_testing;
