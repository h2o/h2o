use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes;
use t::Util;

sub test_origin_frame {
    my ($origin_conf,$expected) = @_;
    my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            return << "EOT";
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/wildcard.key
    certificate-file: examples/h2o/wildcard.crt
    $origin_conf
hosts:
  "*.127.0.0.1.vcap.me:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
EOT
        });

    my $output = run_with_h2get($server, <<"EOR");
    h2g = H2.new
    authority = ARGV[0]
    host = "https://#{authority}"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings()
    i = 0
    while i < 3 do
        f = h2g.read(-1)
        if f.type_num == 12 then
            puts f.len
            puts f.payload.dump
        end

        if f.type == "SETTINGS" and (f.flags == ACK) then
            # ignore
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
        end
        i += 1
    end
EOR

    chomp $output;
    is $output, $expected;
}

test_origin_frame('', '');
test_origin_frame('http2-origin-frame: [ ]', "0\n\"\"");
test_origin_frame('http2-origin-frame: [ "https://a.127.0.0.1.vcap.me" ]', "28\n\"\\000\\032https://a.127.0.0.1.vcap.me\"");
test_origin_frame('http2-origin-frame: [ "https://a.127.0.0.1.vcap.me", "https://b.127.0.0.1.vcap.me" ]', "56\n\"\\000\\032https://a.127.0.0.1.vcap.me\\000\\032https://b.127.0.0.1.vcap.me\"");
done_testing();
