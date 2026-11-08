use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};
plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

# Hop-by-hop header fields are not part of the semantics being exchanged between h2o and the applications. They are not exposed to
# the applications, and applications trying to use them see an exception, except for `connection: close`.

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi"],
    is_ready => sub { check_port($upstream_port) },
);

my $server = spawn_h2o(<< "EOT");
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
      /response:
        - mruby.handler: |
            proc {|env|
              name, value = env["QUERY_STRING"].split("=", 2)
              [200, {name => value}, ["hello"]]
            }
      /early-hints:
        - mruby.handler: |
            proc {|env|
              name, value = env["QUERY_STRING"].split("=", 2)
              begin
                env["rack.early_hints"].call({name => value})
                [200, {}, ["hello"]]
              rescue => e
                [500, {}, [e.message]]
              end
            }
      /http-request:
        - mruby.handler: |
            proc {|env|
              name, value = env["QUERY_STRING"].split("=", 2)
              begin
                status, headers, body = http_request("http://127.0.0.1:$upstream_port/echo-headers", {:headers => {name => value}}).join
                [status, {"x-upstream-headers" => headers.keys.sort.join(",")}, body]
              rescue => e
                [500, {}, [e.message]]
              end
            }
EOT

sub fetch {
    my ($path, @headers) = @_;
    my $resp = `curl --silent --show-error --dump-header /dev/stdout @{[ join " ", map { "-H '$_'" } @headers ]} 'http://127.0.0.1:$server->{port}$path' 2>&1`;
    # skip informational responses
    $resp =~ s{^HTTP/[^ ]* 1\d\d .*?\r\n\r\n}{}s while $resp =~ m{^HTTP/[^ ]* 1\d\d };
    my ($status) = $resp =~ m{^HTTP/[^ ]* (\d+)};
    my ($headers, $body) = $resp =~ m{^(.*?)\r\n\r\n(.*)}s;
    return ($status, $body, $headers);
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

subtest "response" => sub {
    my ($status, $body, $headers) = fetch("/response?x-foo=bar");
    is $status, 200, "status";
    like $headers, qr{^x-foo: bar\r$}im, "header";
    unlike $headers, qr{^connection: close\r$}im, "connection is kept";
    for my $name (qw(connection Connection)) {
        ($status, $body, $headers) = fetch("/response?$name=close");
        is $status, 200, "$name: close status";
        like $headers, qr{^connection: close\r$}im, "$name: close is propagated to HTTP/1";
    }
    for my $kv (qw(transfer-encoding=chunked connection=keep-alive keep-alive=300 upgrade=websocket)) {
        ($status, $body, $headers) = fetch("/response?$kv");
        is $status, 500, "$kv status";
    }
};

subtest "early hints" => sub {
    my ($status, $body) = fetch("/early-hints?x-foo=bar");
    is $status, 200, "status";
    is $body, "hello", "body";
    ($status, $body) = fetch("/early-hints?connection=close");
    is $status, 200, "connection: close is ignored";
    ($status, $body) = fetch("/early-hints?transfer-encoding=chunked");
    is $status, 500, "transfer-encoding status";
    is $body, "hop-by-hop header field cannot be used: transfer-encoding", "transfer-encoding body";
};

subtest "http_request" => sub {
    my ($status, $body, $headers) = fetch("/http-request?x-foo=bar");
    is $status, 200, "status";
    like $body, qr{^x-foo: bar$}m, "header is sent";
    like $headers, qr{^x-upstream-headers: .*content-type}im, "response headers are exposed";
    unlike $headers, qr{^x-upstream-headers: .*connection}im, "hop-by-hop response headers are not exposed";
    unlike $body, qr{^connection: close$}m, "connection is kept";
    ($status, $body) = fetch("/http-request?connection=close");
    is $status, 200, "connection: close status";
    like $body, qr{^connection: close$}m, "connection: close is propagated to HTTP/1";
    for my $kv (qw(transfer-encoding=chunked connection=keep-alive te=trailers)) {
        ($status, $body) = fetch("/http-request?$kv");
        is $status, 500, "$kv status";
        my $name = (split /=/, $kv)[0];
        is $body, "hop-by-hop header field cannot be used: $name", "$kv body";
    }
};

undef $server;

done_testing;
