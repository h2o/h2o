use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port check_port);
use Scope::Guard qw(scope_guard);
use Test::More;
use Test::Exception;
use Time::HiRes;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

sub get {
    my ($proto, $port, $curl, $path) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my $curl_cmd = "$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port$path";
    local $SIG{ALRM} = sub { die };
    alarm(3);
    my ($headers, $body) = eval { run_prog($curl_cmd) };
    my $timeout = !! $@;
    alarm(0);
    die 'timeout' if $timeout;
    ($headers, $body);
}

sub live_check {
    my ($proto, $port, $curl) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    lives_ok {
        my ($headers, $body) = get($proto, $port, $curl, '/live-check');
        like $headers, qr{^HTTP/[0-9.]+ 200}is, 'live status check';
    } 'live check';
};

my $tempdir = tempdir(CLEANUP => 1);
my $access_log_file = "$tempdir/access.log";
my $error_log_file = "$tempdir/error.log";

sub read_logs {
   map {
       my $fn = $_;
       open my $fh, "<", $fn or die "failed to open $fn:$!";
       [ map { my $l = $_; chomp $l; $l } <$fh> ];
   } @_;
}

subtest 'middleware' => sub {
    subtest 'basic' => sub {
        my $empty_port = empty_port();
        my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /:
        - mruby.handler: |
            proc {|env|
              H2O.next.call(env)
            }
        # this specifies an empty port, so the connection will fail immediately and emit error log
        - proxy.reverse.url: http://127.0.0.1:$empty_port
  "127.0.0.1:$tls_port":
    paths: *paths
access-log:
  path: $access_log_file
  format: "%{error}x"
error-log: $error_log_file
EOT
            });
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            truncate $access_log_file, 0;
            truncate $error_log_file, 0;

            my ($headers, $body) = get($proto, $port, $curl, '/');
            like $headers, qr{^HTTP/[0-9.]+ 502}is;

            my ($access_logs, $error_logs) = read_logs($access_log_file, $error_log_file);
            is scalar(@$access_logs), 1, 'access log count';
            isnt scalar(@$error_logs), 0, 'error log count';
            is $access_logs->[0], '[lib/core/proxy.c] in request:/:connection failed', 'access log';
            is $error_logs->[-1], '[lib/core/proxy.c] in request:/:connection failed', 'error log';
        });
    };

    subtest 'wrap error stream' => sub {
        my $empty_port = empty_port();
        my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /:
        - mruby.handler: |
            class WrapErrorStream
              def initialize(orig)
                \@orig = orig
                \@buf = []
              end
              def write(msg)
                \@orig.write(msg)
                \@buf.push(msg)
              end
              def buf
                \@buf
              end
            end
            proc {|env|
              es = WrapErrorStream.new(env['rack.errors'])
              env['rack.errors'] = es
              resp = H2O.next.call(env)
              [resp[0], {}, [es.buf.join("\\n")]]
            }
        - proxy.reverse.url: http://127.0.0.1:$empty_port # ditto
  "127.0.0.1:$tls_port":
    paths: *paths
access-log:
  path: $access_log_file
  format: "%{error}x"
error-log: $error_log_file
EOT
            });
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            truncate $access_log_file, 0;
            truncate $error_log_file, 0;

            my ($headers, $body) = get($proto, $port, $curl, '/');
            like $headers, qr{^HTTP/[0-9.]+ 502}is;

            my ($access_logs, $error_logs) = read_logs($access_log_file, $error_log_file);
            is scalar(@$access_logs), 1, 'access log count';
            isnt scalar(@$error_logs), 0, 'error log count';
            is $access_logs->[0], '[lib/core/proxy.c] in request:/:connection failed', 'access log';
            is $error_logs->[-1], '[lib/core/proxy.c] in request:/:connection failed', 'error log';
            is $body, '[lib/core/proxy.c] in request:/:connection failed', 'wrapped buffer';
        });
    };

    subtest 'parent request is disposed before subrequest emits error logs' => sub {
        my $spawner = sub {
            my $upstream_port = empty_port();

            # create upstream
            my $upstream_pid = fork;
            die "fork failed: $!" unless defined $upstream_pid;
            unless ($upstream_pid) {
                my $sock = IO::Socket::INET->new(
                    LocalHost => '127.0.0.1',
                    LocalPort => $upstream_port,
                    Proto => 'tcp',
                    Listen => 1,
                    Reuse => 1,
                ) or die $!;
                my $client = $sock->accept;
                while (1) {
                    my $req = '';
                    $client->recv($req, 1024);
                    last if $req =~ /\r\n\r\n$/;
                }
                $client->send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                Time::HiRes::sleep 0.5;
                $client->send("X"); # this causes an invalid chunk error in proxy handler
                $client->close;
                exit 0;
            };
            my $upstream = scope_guard(sub {
                kill 'TERM', $upstream_pid;
                while (waitpid($upstream_pid, 0) != $upstream_pid) {}
            });
            my $server = spawn_h2o(sub {
                my ($port, $tls_port) = @_;
                << "EOT";
hosts:
  "127.0.0.1:$port":
    paths: &paths
      /live-check:
        - mruby.handler: proc {|env| [200, {}, []] }
      /:
        - mruby.handler: |
            proc {|env|
              resp = H2O.next.call(env)
              [resp[0], resp[1], []] # respond without waiting body
            }
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
  "127.0.0.1:$tls_port":
    paths: *paths
access-log:
  path: $access_log_file
  format: "%{error}x"
error-log: $error_log_file
EOT
            });
            ($server, $upstream);
        };

        run_with_curl({}, sub {
            my ($proto, undef, $curl) = @_;
            truncate $access_log_file, 0;
            truncate $error_log_file, 0;

            my ($server, $upstream) = $spawner->();
            my $port = $proto eq 'http' ? $server->{port} : $server->{tls_port};

            my ($headers, $body) = get($proto, $port, $curl, '/');
            like $headers, qr{^HTTP/[0-9.]+ 200}is;

            # after 0.5 sec, the proxy handler should emit an invalid chunk error
            sleep 1;

            my ($access_logs, $error_logs) = read_logs($access_log_file, $error_log_file);

            is scalar(@$access_logs), 1, 'access log count';
            isnt scalar(@$error_logs), 0, 'error log count';
            is $access_logs->[0], '', 'access log';
            is $error_logs->[-1], '[lib/core/proxy.c] in request:/:failed to parse the response (chunked)', 'error log';

            live_check($proto, $port, $curl);
        });
    };
};

done_testing();
