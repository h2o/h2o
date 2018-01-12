use strict;
use warnings;
use File::Temp qw(tempfile);
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Socket qw(SOMAXCONN);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $upstream_port = empty_port();

# we can establish SOMAXCONN sockets without actually accepting them
my $listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $upstream_port,
    Listen    => SOMAXCONN,
) or die "failed to listen to 127.0.0.1:$upstream_port:$!";

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $huge_file_size = 100 * 1024 * 1024;
my $huge_file = create_data_file($huge_file_size);

my $doit = sub {
    my ($proto, $opt, $port) = @_;

    my $before = time();
    `nghttp -t 10 $opt -nv -d $huge_file $proto://127.0.0.1:$port/echo`;
    my $after = time();
    cmp_ok $after - $before, ">=", 10, "Timeout was triggered by nghttp";
};

subtest 'http (upgrade)' => sub {
    $doit->('http', '-u', $server->{port});
};
subtest 'https' => sub {
    $doit->('https', '', $server->{tls_port});
};

done_testing();
