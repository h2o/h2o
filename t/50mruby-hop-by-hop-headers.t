use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};
plan skip_all => 'curl not found'
    unless prog_exists('curl');

# Hop-by-hop header fields are not part of the semantics being exchanged between h2o and the applications. They are not exposed to
# the applications, and applications trying to use them see an exception, except for `connection: close`.

my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /env:
        - mruby.handler: |
            proc {|env|
              [200, {}, [env.keys.select {|k| k[0, 5] == "HTTP_" }.sort.join(",")]]
            }
      /next:
        - mruby.handler: |
            proc {|env|
              name, value = env["QUERY_STRING"].split("=", 2)
              subenv = {}
              env.each {|k, v| subenv[k] = v unless k[0, 5] == "HTTP_" }
              subenv[name] = value
              begin
                H2O.next.call(subenv)
              rescue => e
                [500, {}, [e.message]]
              end
            }
        - mruby.handler: |
            proc {|env|
              [200, {}, [env.keys.select {|k| k[0, 5] == "HTTP_" }.sort.join(",")]]
            }
EOT

sub fetch {
    my ($path, @headers) = @_;
    my $resp = `curl --silent --show-error --dump-header /dev/stdout @{[ join " ", map { "-H '$_'" } @headers ]} 'http://127.0.0.1:$server->{port}$path' 2>&1`;
    my ($status) = $resp =~ m{^HTTP/[^ ]* (\d+)};
    my ($body) = $resp =~ m{\r\n\r\n(.*)}s;
    return ($status, $body);
}

subtest "env" => sub {
    my ($status, $body) = fetch("/env", "User-Agent:", "Accept:", "Connection: keep-alive", "Keep-Alive: 300", "TE: trailers",
        "X-Foo: bar");
    is $status, 200, "status";
    is $body, "HTTP_HOST,HTTP_X_FOO", "hop-by-hop header fields are not exposed";
    ($status, $body) = fetch("/env", "User-Agent:", "Accept:", "Connection: keep-alive");
    is $status, 200, "status (hop-by-hop header fields only)";
    is $body, "HTTP_HOST", "body (hop-by-hop header fields only)";
};

subtest "H2O.next" => sub {
    my ($status, $body) = fetch("/next?HTTP_X_FOO=bar");
    is $status, 200, "status";
    is $body, "HTTP_HOST,HTTP_X_FOO", "body";
    ($status, $body) = fetch("/next?HTTP_CONNECTION=close");
    is $status, 200, "connection: close is ignored";
    is $body, "HTTP_HOST", "connection: close is not passed";
    for my $kv (qw(HTTP_TRANSFER_ENCODING=chunked HTTP_CONNECTION=keep-alive HTTP_TE=trailers HTTP_UPGRADE=websocket)) {
        ($status, $body) = fetch("/next?$kv");
        is $status, 500, "$kv status";
        my $name = lc substr((split /=/, $kv)[0], 5);
        $name =~ tr/_/-/;
        is $body, "hop-by-hop header field cannot be used: $name", "$kv body";
    }
};

undef $server;

done_testing;
