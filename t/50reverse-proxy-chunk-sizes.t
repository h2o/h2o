use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);


my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub test {
    my ($cl, $size, $trailer) = @_;
    my $file = create_data_file($size);
    my $file_md5 = md5_file($file);
    note("$size, cl:'$cl', trailer:'$trailer', h2c");
    my $resp;
    $resp = `nghttp $cl $trailer -d $file -u http://127.0.0.1:$server->{port}/echo`;
    is md5_hex($resp), $file_md5, "body matches";
    note("$size, cl:'$cl', trailer:'$trailer', h2");
    $resp = `nghttp $cl $trailer -d $file https://127.0.0.1:$server->{tls_port}/echo`;
    is md5_hex($resp), $file_md5, "body matches";
}
my @sizes = ( 1000, 65535, 1000000 );
my @clopts = ( "", "--no-content-length" );
my @tailers = ( "", "--trailer=foo:bar" );

foreach my $cl (@clopts) {
    foreach my $size (@sizes) {
        foreach my $trailer (@tailers) {
            test($cl, $size, $trailer);
        }
    }
}

done_testing();

