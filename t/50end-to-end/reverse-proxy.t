use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

# spawn upstream server
my $upstream_port = empty_port();
my $upstream_guard = spawn_server(
    argv     => [
        qw(plackup -MPlack::App::File -s Starlet --access-log /dev/null -p), $upstream_port, '-e',
        'Plack::App::File->new(root => q(t/50end-to-end/reverse-proxy/docroot))->to_app',
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my %files = map { +($_ => md5_file("t/50end-to-end/reverse-proxy/docroot/$_")) } qw(index.txt halfdome.jpg);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $port = $server->{port};
my $tls_port = $server->{tls_port};

subtest 'curl' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    for (1..4) {
    for my $file (sort keys %files) {
        my $md5 = `curl --silent --show-error http://127.0.0.1:$port/$file | openssl md5 | perl -pe 's/.* //'`;
        is $md5, $files{$file}, "http://127.0.0.1/$file";
        $md5 = `curl --silent --show-error --insecure https://127.0.0.1:$tls_port/$file | openssl md5 | perl -pe 's/.* //'`;
        is $md5, $files{$file}, "https://127.0.0.1/$file";
    }
}
};

subtest 'nghttp' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $doit = sub {
        my ($proto, $port) = @_;
        my $opt = $proto eq 'http' ? '-u' : '';
        for my $file (sort keys %files) {
            my $md5 = `nghttp $opt $proto://127.0.0.1:$port/$file | openssl md5 | perl -pe 's/.* //'`;
            is $md5, $files{$file}, "$proto://127.0.0.1/$file";
        }
        my $out = `nghttp -u -m 10 $proto://127.0.0.1:$port/index.txt`;
        is $out, "hello\n" x 10, "$proto://127.0.0.1/index.txt x 10 times";
    };
    subtest 'http' => sub {
        $doit->('http', $port);
    };
    subtest 'https' => sub {
        plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
            unless openssl_can_negotiate();
        $doit->('https', $tls_port);
    };
};

done_testing;
