use strict;
use warnings;
use Test::More;
use t::Util;
use Time::HiRes qw(time);

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $all_data = do {
    open my $fh, "<", "@{[DOC_ROOT]}/halfdome.jpg"
        or die "failed to open file:@{[DOC_ROOT]}/halfdome.jpg:$!";
    local $/;
    <$fh>;
};

subtest "file" => sub {
    my $server = spawn_h2o(<< "EOT");
throttle-response: ON
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
        header.add: "X-Traffic: 100000"
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        $curl_cmd .= " --silent --show-error";
        my $url = "$proto://127.0.0.1:$port/halfdome.jpg";

        subtest "throttle-to-low-speed" => sub {
            my $start_time = time;
            my $resp = `$curl_cmd $url`;
            my $end_time = time;
            is $resp, $all_data;
            my $speed = length($resp) / ($end_time - $start_time);
            cmp_ok($speed, '<=', 100000 * 1.1); # the implementation may cause response speed is a bit larger than the limitation, especially when file is not big enough.
        };
    });
};

subtest "delayed" => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};

    my $server = spawn_h2o(<< "EOT");
throttle-response: ON
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          Proc.new do |env|
            [
              200,
              { "X-Traffic" => "100000" },
              Class.new do
                def each
                  yield "hello "
                  sleep 1
                  yield "world"
                end
              end.new,
            ]
          end
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        my $start_time = time;
        my $resp = `$curl_cmd --silent --show-error $proto://127.0.0.1:$port/`;
        is $?, 0, "exit status";
        is $resp, "hello world";
        my $elapsed = time - $start_time;
        cmp_ok $elapsed, '>', 0.9;
        cmp_ok $elapsed, '<', 1.3;
    });
};

done_testing();
