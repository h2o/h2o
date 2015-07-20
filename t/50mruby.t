use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub fetch {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return (`curl --silent /dev/stderr -H User-Agent:h2o_mruby_test http://127.0.0.1:$server->{port}/ 2>&1`, $server->{port});
}

sub fetch_header {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1`;
}

sub fetch_uri {
    my ($extra_conf, $uri) = @_;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
$extra_conf
EOT
    return `curl --silent /dev/stderr http://127.0.0.1:$server->{port}/$uri 2>&1`;
}

my ($resp, $port) = fetch(<< 'EOT');
        file.dir: examples/doc_root
        mruby.handler_path: t/50mruby/hello.rb
EOT
is $resp, "hello from h2o_mruby\n", "resoponse body from mruby";

($resp, $port) = fetch(<< 'EOT');
        file.dir: examples/doc_root
        mruby.handler_path: t/50mruby/max_header.rb
EOT
is $resp, "100", "H2O.max_headers method";

($resp, $port) = fetch(<< 'EOT');
        file.dir: examples/doc_root
        mruby.handler_path: t/50mruby/headers_in.rb
EOT
is $resp, "new-h2o_mruby_test", "H2O::Request#headers_in test";

$resp = fetch_header(<< 'EOT');
        file.dir: examples/doc_root
        mruby.handler_path: t/50mruby/headers_out.rb
EOT
like $resp, qr/^new-header:.*\Wh2o-mruby\W/im, "H2O::Response#headers_out test";

($resp, $port) = fetch(<< 'EOT');
        file.dir: examples/doc_root
        mruby.handler_path: t/50mruby/return_status.rb
EOT
is $resp, "not found", "H2O.return with status code test";

($resp, $port)= fetch(<< 'EOT');
        file.dir: t/50mruby/
        mruby.handler_path: t/50mruby/return_declined.rb
EOT
is $resp, "I'm index.html\n", "H2O.return with declined code test";

($resp, $port) = fetch(<< 'EOT');
        file.dir: t/50mruby/
        mruby.handler_path: t/50mruby/method.rb
EOT
is $resp, "GET", "H2O::Request#method test";

$resp = fetch_uri(<< 'EOT', 'index.html?a=1');
        file.dir: t/50mruby/
        mruby.handler_path: t/50mruby/query.rb
EOT
is $resp, "?a=1", "H2O::Request#query test";

$resp = fetch_uri(<< 'EOT', 'index.html?a=1');
        file.dir: t/50mruby/
        mruby.handler_path: t/50mruby/uri.rb
EOT
is $resp, "/index.html?a=1", "H2O::Request#uri test";

($resp, $port) = fetch(<< 'EOT');
        file.dir: t/50mruby/
        mruby.handler_path: t/50mruby/hostname.rb
EOT
is $resp, "127.0.0.1:$port", "H2O::Request#hostname test";

done_testing();
