use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};
plan skip_all => "h2get not found"
    unless h2get_exists();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          proc {|env|
            [200, {}, ["x-trailer:#{env["HTTP_X_TRAILER"].inspect}"]]
          }
EOT

sub send_request_with_trailers {
    my $trailer_value = shift;
    run_with_h2get_simple($server, <<"EOR");
        req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/" }
        h2g.send_headers(req, 1, END_HEADERS)
        h2g.send_data(1, 0, "hello")
        h2g.send_headers({ "x-trailer" => "$trailer_value" }, 1, END_HEADERS | END_STREAM)
        while true
            f = h2g.read(1000)
            break if f == nil
            puts f.to_s
            puts "body:#{f.payload}" if f.type == "DATA"
        end
EOR
}

subtest "trailers are not merged into headers" => sub {
    my $output = send_request_with_trailers("abc");
    like $output, qr{':status' => '200'}, "status";
    like $output, qr{^body:x-trailer:nil$}m, "trailer is not visible as a header";
};

subtest "invalid character in trailers" => sub {
    my $output = send_request_with_trailers("a\\x01b");
    like $output, qr{RST_STREAM frame <[^>]*stream_id=1>\s*error_code => 1\n}s, "RST_STREAM(PROTOCOL_ERROR)";
    unlike $output, qr{GOAWAY}, "no GOAWAY";
};

done_testing();
