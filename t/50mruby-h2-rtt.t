use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'HTTP/2' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler-file: t/assets/50mruby-h2o-rtt.rb
EOT
    (undef, my $body) = run_prog("curl --http2 -sS http://127.0.0.1:$server->{port}/");
    like $body, qr{^RTT = \d+$};
    if ($body =~ qr{^RTT = (\d+)$}) {
        my $rtt = $1;
        # In the local test this can be 0us.
        cmp_ok $rtt, '>=', 0, "The round-trip time estimate is $rtt microseconds.";
    }
};

subtest 'HTTP/1.1' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        mruby.handler-file: t/assets/50mruby-h2o-rtt.rb
EOT
    (undef, my $body) = run_prog("curl --http1.1 -sS http://127.0.0.1:$server->{port}/");
    like $body, qr{^RTT = N/A$};
};

done_testing;
