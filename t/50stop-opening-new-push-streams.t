use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 2
hosts:
  default:
    paths:
      "/":
        - mruby.handler: |
            proc {|env|
              sleep 1
              [399, { 'link' => '</index.js>; rel=preload; as=script' }, []]
            }
        - file.dir: @{[ DOC_ROOT ]}
EOT

my $output = run_with_h2get_simple($server, <<"EOR");
req = {
    ":method" => "GET",
    ":authority" => host,
    ":scheme" => "https",
    ":path" => "/",
}
h2g.send_headers(req, 1, END_HEADERS | END_STREAM)
h2g.send_goaway(0, 0)
loop do
    f = h2g.read(2000)
    if f == nil
        puts "timeout"
        exit 1
    end
    if f.type == 'PUSH_PROMISE'
        puts "push promise found"
        exit 1
    end
    puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
end
EOR

unlike $output, qr{push promise found}, 'push stream must not be started after goaway received';
done_testing();
