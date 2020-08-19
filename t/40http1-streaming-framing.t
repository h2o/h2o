use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $upstream_port = empty_port();
my $upstream = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
) or die "cannot create socket: $!";

sub do_upstream {
    my $expected_framing = shift;
    my $client = $upstream->accept;
    my $ok = 0;
    while (my $buf = <$client>) {
        $ok = 1 if $buf =~ /$expected_framing/;
        last if $buf eq "\r\n";
    }
    ok($ok == 1, "Saw expecting framing: $expected_framing");
}

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT


my $huge_file_size = 50 * 1024 * 1024;
my $huge_file = create_data_file($huge_file_size);
# test that we'll proxy content-length as content-length if possible
open(CURL, "curl -s -d \@$huge_file --http1.1 'http://127.0.0.1:$server->{port}' 2> /dev/null | ");
do_upstream("content-length");
close(CURL);

open(CURL, "curl -s -d \@$huge_file -Htransfer-encoding:chunked --http1.1 'http://127.0.0.1:$server->{port}' 2> /dev/null | ");
do_upstream("transfer-encoding");
close(CURL);

done_testing();
