use strict;
use warnings;
use Test::More;
use Net::EmptyPort qw(empty_port);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  initcwnd: 30
  quic:
    max-streams-bidi: 1000
    retry: OFF
    amp-limit: 5
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+*"
        proxy.timeout.io: 30000
        proxy.timeout.connect: 1000
      "/hello":
        file.file: examples/doc_root.alternate/index.txt
EOT

# The value for -S must be higher than the kernel's connect timeout in seconds.
# Linux uses exponential backoff with the sysctl net.ipv4.tcp_syn_retries
# as an input.  I have used "sysctl net.ipv4.tcp_syn_retries=2" with good results.

subtest "I'm doing science...", sub {
    my $content = `${client_prog} -3 -S 15 -x 151.101.53.57:4433 https://127.0.0.1:${quic_port}/ 2>&1 | tee /dev/stderr`;
    like $content, qr{timeout}, "content";
    unlike $content, qr{Assertion}, "assert";
};

subtest "...and I'm still alive", sub {
    my $content = `${client_prog} -3 https://127.0.0.1:${quic_port}/hello`;
    like $content, qr{hello}, "content";
};

done_testing;
