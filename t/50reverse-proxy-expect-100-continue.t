use strict;
use warnings;
use Test::More;
use Time::HiRes;
use t::Util;
use IO::Select;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port);

plan skip_all => "h2get not found"
    unless h2get_exists();

plan skip_all => "nc not found"
    unless prog_exists("nc");

subtest 'h1 upstream' => sub {
    my $h1_upstream_port = empty_port();

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /h1:
        proxy.expect: ON
        proxy.reverse.url: http://127.0.0.1:$h1_upstream_port
EOT

    my $upstream = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $h1_upstream_port,
        Proto => 'tcp',
        Listen => 1,
    ) or die $!;

    subtest 'basic' => sub {
        my $c = spawn_forked(sub {
            print `curl --http2 -s -X POST --data-binary xxxxx http://127.0.0.1:$server->{port}/h1`;
        });

        my $client = $upstream->accept;
        my $chunk;

        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        like $header, qr/expect: *100-continue/i;

        note 'test that h2o never send req body before this server respond with 100 continue';
        ok(! IO::Select->new([ $client ])->can_read(1));

        note 'send 100 continue';
        $client->syswrite("HTTP/1.1 100 Continue\r\n\r\n");

        note 'then h2o should have sent the body';
        ok(IO::Select->new([ $client ])->can_read(1));

        note 'read body';
        my $body;
        is $client->sysread($body, 5), 5;
        is $body, 'xxxxx';

        my $content = "Good waiting! You're awesome!";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);

        my ($cout) = $c->{wait}->();

        is $cout, $content;
    };

    subtest 'no 100 response' => sub {
        my $c = spawn_forked(sub {
            print `curl --http2 -s -X POST --data-binary xxxxx http://127.0.0.1:$server->{port}/h1`;
        });

        my $client = $upstream->accept;
        my $chunk;

        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        like $header, qr/expect: *100-continue/i;

        note 'test that h2o never send req body before this server respond with 100 continue';
        ok(! IO::Select->new([ $client ])->can_read(1));

        my $content = "What do you expect from me? Just zip it and dig in!";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);

        note 'then h2o should have sent the body';
        ok(IO::Select->new([ $client ])->can_read(1));

        note 'read body';
        my $body;
        is $client->sysread($body, 5), 5;
        is $body, 'xxxxx';

        my ($cout) = $c->{wait}->();

        is $cout, $content;
    };

    subtest 'no body' => sub {
        my $c = spawn_forked(sub {
            print `curl -X GET -s http://127.0.0.1:$server->{port}/h1`;
        });

        my $client = $upstream->accept;
        my $chunk;

        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        unlike $header, qr/expect: *100-continue/i;

        my $content = "Hello, you sent no body";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);

        my ($cout) = $c->{wait}->();

        is $cout, $content;
    };

};

subtest 'h2 upstream' => sub {
    my $backend = spawn_h2get_backend(<< 'EOT');
if f.type == 'HEADERS'
  exit 1 unless f.to_s.include? "'expect' => '100-continue'"
  # make sure no DATA frame is seen
  while true do
    should_be_nil = conn.read(2000)
    # there might be a SETTINGS ack frame in flight, ignore
    next if should_be_nil != nil and should_be_nil.type == 'SETTINGS'
    exit 1 if should_be_nil != nil
    break
  end
  # Send 100
  resp = {
    ":status" => "100",
  }
  conn.send_headers(resp, f.stream_id, END_HEADERS)
  # Expect a DATA frame now
  should_be_data_frame = conn.read(2000)
  exit 1 if should_be_data_frame == nil or should_be_data_frame.type != 'DATA'
  resp = {
    ":status" => "200",
  }
  conn.send_headers(resp, f.stream_id, END_HEADERS | END_STREAM)
  puts "OK"
end
EOT
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.expect: ON
        proxy.reverse.url: https://127.0.0.1:$backend->{tls_port}/
        proxy.http2.ratio: 100
        proxy.ssl.verify-peer: OFF
access-log: /dev/stdout
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($headers, $body) = run_prog("$curl --data 'request body' --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/");
        like $headers, qr{^HTTP/[0-9.]+ 200}is, '200 status';
    });
    my ($out, $err) = $backend->{kill}->();
    like $out, qr/OK\nOK\nOK\n/, "server side tests successful";
    like $err, qr/^$/, "server stderr is empty";
};

subtest 'h3 upstream' => sub {
    plan skip_all => 'TODO';
};

subtest 'forward' => sub {
    my $upstream_port = empty_port();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.expect: FORWARD
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    my $upstream = spawn_server(
        argv => [
            qw(plackup -s Standalone --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub {
            check_port($upstream_port);
        },
    );

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($headers, $body);

        ($headers, $body) = run_prog("$curl -H 'expect: 100-continue' --data 'request body' --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/echo-headers");
        like $headers, qr{^HTTP/[0-9.]+ 200}is, '200 status';
        like $body, qr{^expect: 100-continue$}im, 'upstream received forwarded expect header';

        ($headers, $body) = run_prog("$curl -H 'expect: 100-continue' --data 'request body' --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/echo");
        like $headers, qr{^HTTP/[0-9.]+ 200}is, '200 status';
        is $body, 'request body', 'body works';

        ($headers, $body) = run_prog("$curl --verbose -H 'expect: 100-continue' --data 'request body' --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/1xx");
        like $headers, qr{Done waiting for 100-continue.+HTTP/[0-9.]+ 200}is, '100 then 200 status';
    });
};

done_testing;
