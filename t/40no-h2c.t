use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
http1-upgrade-to-http2: OFF
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

my ($head, $body) = run_prog("curl --http2 -sv http://127.0.0.1:$server->{port}/");
like $head, qr{HTTP/1.1 301 Moved Permanently}, "Status code is 301";
like $head, qr{location: https://127.0.0.1:$server->{port}/}, "location header contains expected value";
is $body, '<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF="https://127.0.0.1:'.$server->{port}.'/">here</A>', "Body contains rewritten destination";

done_testing;
