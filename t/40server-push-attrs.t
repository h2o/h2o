use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;
plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');
plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "basic" => sub {
    # spawn upstream
    my $upstream_port = empty_port();
    my $upstream = spawn_server(
        argv     => [
            qw(plackup -s Starlet --access-log /dev/null -p), $upstream_port, ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($upstream_port);
        },
    );
    # spawn server
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /assets:
        file.dir: @{[DOC_ROOT]}
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

    my $pushes_encoded = "</assets/index.txt.gz>; rel=preload, </assets/index.txt.gz?1>; rel=preload, </assets/index.txt.gz?nopush>; rel=preload; nopush";
    $pushes_encoded =~ s{([^A-Za-z0-9_])}{sprintf "%%%02x", ord $1}eg;
    my $resp = `nghttp -vn --stat 'https://127.0.0.1:$server->{tls_port}/push-attr?pushes=$pushes_encoded'`;
    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz}is, "index.txt.gz is pushed";
    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?1}is, "index.txt.gz?1 is pushed";
    unlike $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?nopush}is, "index.txt.gz?nopush isn't pushed";

    $pushes_encoded = "</assets/index.txt.gz>; rel=preload, </assets/index.txt.gz?1>; rel=preload, </assets/index.txt.gz?nopush>; rel=preload; nopush, </assets/index.txt.gz?push-only>; rel=preload; x-http2-push-only";
    $pushes_encoded =~ s{([^A-Za-z0-9_])}{sprintf "%%%02x", ord $1}eg;
    $resp = `nghttp -vn --stat 'https://127.0.0.1:$server->{tls_port}/push-attr?pushes=$pushes_encoded'`;

    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz}is, "index.txt.gz is pushed";
    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?1}is, "index.txt.gz?1 is pushed";
    unlike $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?nopush}is, "index.txt.gz?nopush isn't pushed";
    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?push-only}is, "index.txt.gz?push-only is pushed";
    like $resp, qr{link: </assets/index\.txt\.gz>; rel=preload, </assets/index\.txt\.gz\?1>; rel=preload, </assets/index\.txt\.gz\?nopush>; rel=preload; nopush\n}, "push-only doesn't appear in the link header";

    # Check that the header is removed if there's only one link with x-http2-push-only
    $pushes_encoded = "</assets/index.txt.gz?push-only>; rel=preload; x-http2-push-only";
    $pushes_encoded =~ s{([^A-Za-z0-9_])}{sprintf "%%%02x", ord $1}eg;
    $resp = `nghttp -vn --stat 'https://127.0.0.1:$server->{tls_port}/push-attr?pushes=$pushes_encoded'`;

    like $resp, qr{\nid\s*responseEnd\s.*\s/assets/index\.txt\.gz\?push-only}is, "index.txt.gz?push-only is pushed";
    unlike $resp, qr{link:\s*\n}, "push-only doesn't appear in the link header";
};


done_testing;
