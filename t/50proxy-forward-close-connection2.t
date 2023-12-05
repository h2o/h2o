use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $keep_alive_upstream_port = empty_port();
my $close_conn_upstream_port = empty_port();
my $curl = 'curl -sSi';

my $g1 = one_shot_http_upstream("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nOk", $keep_alive_upstream_port);
my $g2 = one_shot_http_upstream("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOk", $close_conn_upstream_port);

my $doit = sub {
    my ($conf, $tests) = @_;
    my $server = spawn_h2o($conf);
    foreach my $url ( keys %$tests ) {
        my $expect = $tests->{$url};
        my ($err, $out) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}$url");
        diag $err;
        like $out, qr/^Connection: $expect/mi, "url=$url connection=$expect";
    }
};

subtest 'per-path ON' => sub {
    my $conf = << "EOT";
hosts:
  default:
    paths:
      "/ka-origin-1":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
      "/cc-origin-1":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
      "/ka-origin-2":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
        proxy.forward.close-connection: ON
      "/cc-origin-2":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
        proxy.forward.close-connection: ON
EOT

    $doit->($conf, {
      "/ka-origin-1" => "keep-alive",
      "/cc-origin-1" => "keep-alive",
      "/ka-origin-2" => "keep-alive",
      "/cc-origin-2" => "close",
    });
};

subtest 'per-host ON' => sub {
    my $conf = << "EOT";
hosts:
  default:
    proxy.forward.close-connection: ON
    paths:
      "/ka-origin":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
      "/cc-origin":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
EOT

    $doit->($conf, {
      "/ka-origin" => "keep-alive",
      "/cc-origin" => "close",
    });
};

subtest 'top-level ON, per-path override OFF' => sub {
    my $conf = << "EOT";
proxy.forward.close-connection: ON
hosts:
  default:
    paths:
      "/ka-origin-1":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
      "/cc-origin-1":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
      "/ka-origin-2":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
        proxy.forward.close-connection: OFF
      "/cc-origin-2":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
        proxy.forward.close-connection: OFF
EOT

    $doit->($conf, {
      "/ka-origin-1" => "keep-alive",
      "/cc-origin-1" => "close",
      "/ka-origin-2" => "keep-alive",
      "/cc-origin-2" => "keep-alive",
    });
};

subtest 'top-level OFF, per-path override ON' => sub {
    my $conf = << "EOT";
proxy.forward.close-connection: OFF
hosts:
  default:
    paths:
      "/ka-origin-1":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
      "/cc-origin-1":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
      "/ka-origin-2":
        proxy.reverse.url: http://127.0.0.1:$keep_alive_upstream_port
        proxy.forward.close-connection: ON
      "/cc-origin-2":
        proxy.reverse.url: http://127.0.0.1:$close_conn_upstream_port
        proxy.forward.close-connection: ON
EOT

    $doit->($conf, {
      "/ka-origin-1" => "keep-alive",
      "/cc-origin-1" => "keep-alive",
      "/ka-origin-2" => "keep-alive",
      "/cc-origin-2" => "close",
    });
};

done_testing();
