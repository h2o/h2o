use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(time);
use IO::Socket::INET;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

plan skip_all => 'curl not found'
    unless prog_exists('curl');


sub create_http1_upstream {
    my $upstream_port = empty_port();

    # creating a listening socket
    my $socket = new IO::Socket::INET (
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1
    );
    die "cannot create socket $!\n" unless $socket;
    my $serve = sub {
        my $client_socket = $socket->accept();

        my $data = "";
        print($client_socket->recv($data, 4096));

        my $header = "HTTP/1.0 200 Ok\r\nConnection: close\r\n\r\n";
        $client_socket->send($header);
        my $start = time();
        for (1..200) {
            $client_socket->send("abcabcabc\n" x 100000) == 1000000
                 or die "failed to write to socket:$!";
        }
        my $duration = time() - $start;
        $client_socket->send("\n$duration");

        close($client_socket)
            or die "close failed:$!";
    };
    return +{ guard => $socket, port => $upstream_port, serve => $serve };
};

sub create_http2_upstream {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      "/":
        - mruby.handler: |
            proc {|env|
              [200, {}, Class.new do
                def each
                  start = Time.now
                  200.times { yield "abcabcabc\n" * 100000 }
                  duration = Time.now - start
                  yield "\n#{duration}"
                end
              end.new]
            }
EOT
    return +{ guard => $server, port => $server->{port} };
}

my $http1_upstream = create_http1_upstream();
my $http2_upstream = create_http2_upstream();

sub max_buffer_size_test {
    my ($max_on, $http2) = @_;

    my $directive = "";
    if ($max_on == 1) {
        $directive = "proxy.max-buffer-size: 1000";
    }
    my $upstream = $http2 ? $http2_upstream : $http1_upstream;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:@{[$upstream->{port}]}
        $directive
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $start = time();
diag $start;
        open(CURL, "$curl --limit-rate 40M -s $proto://127.0.0.1:$port/ 2>&1 | tail -n 1 |");
diag 'serving..';
        $upstream->{serve}->() if $upstream->{serve};
diag 'served.';
diag 'fetching..';
        my $resp = <CURL>;
diag 'fetched.';
        my $duration = time() - $start;
        # handle_curl() writes 200M and curl downloads at 40M/s, so it
        # should take about 5 seconds to download
        # when the proxy.max-buffer-size is not set, H2O will buffer the
        # whole 200M, so the time spent in handler_curl() will be very small.
        # OTOH, when the setting is set, it will take about the same time
        # to write to H2O, as it will take for curl download  the response
diag $duration;
diag $resp;
        if ($max_on) {
            cmp_ok($duration - $resp, '<=', 2, "Writing to H2O was as fast as the curl download");
        } else {
            cmp_ok($duration - $resp, '>', 3, "Writing to H2O was much faster than the curl download");
        }
    });
}

subtest 'http1' => sub {
    diag 'hoge1';
    subtest "no max buffer size" => sub {
        max_buffer_size_test(0, 0);
    };
    # diag 'hoge2';
    # subtest "max buffer size" => sub {
    #     max_buffer_size_test(1, 0);
    # };
};

# subtest 'http2' => sub {
#     diag 'hoge1';
#     subtest "no max buffer size" => sub {
#         max_buffer_size_test(0, 1);
#     };
#     diag 'hoge2';
#     subtest "max buffer size" => sub {
#         max_buffer_size_test(1, 1);
#     };
# };

done_testing();
