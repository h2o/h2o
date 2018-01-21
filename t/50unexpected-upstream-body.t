use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes;
use t::Util;


sub nc_get {
    my ($server, $path) = @_;
    my $resp = `echo 'GET $path HTTP/1.1\\r\\n\\r\\n' | nc 127.0.0.1 $server->{port}`;
    (undef, my $body) = split(/\r\n\r\n/, $resp, 2);
    $body;
}

sub nghttp_get {
    my ($server, $path) = @_; 
    my $out = `nghttp -vn 'https://127.0.0.1:$server->{tls_port}$path'`;
    my $payload_size = 0;
    while ($out =~ /recv DATA frame <length=(\d+)/g) {
        $payload_size += $1;
    }
    ($payload_size, $out);
}

sub create_upstream {
    my (@plackup_opts) = @_;
    my $port = empty_port();
    my ($guard, $pid) = spawn_server(
        argv => [
            qw(plackup), @plackup_opts, qw(--access-log /dev/null --listen), "127.0.0.1:$port",
            ASSETS_DIR . "/upstream.psgi",
        ],
        is_ready => sub { check_port($port) },
    );
    +{ guard => $guard, pid => $pid, port => $port };
}

sub doit {
    my ($spawner, $chunked_enabled) = @_;

    subtest 'http1-client' => sub {
        plan skip_all => "nc not found"
            unless prog_exists("nc");

        subtest 'oversize body' => sub {
            my ($server, $upstream) = $spawner->();
            my $body = nc_get($server, '/content?size=100000&cl=80000');
            is length($body), 80000, 'body size';
        };

        subtest 'incomplete body' => sub {
            my ($server, $upstream) = $spawner->();
            my $body = nc_get($server, '/content?size=100000&cl=120000');
            is length($body), 100000, 'body size';
        };

        if ($chunked_enabled) {
            subtest 'chunked upstream unexpectedly closed' => sub {
                my ($server, $upstream) = $spawner->();
                local $SIG{ALRM} = sub { kill 'KILL', $upstream->{pid} };
                alarm(1);
                my $body = nc_get($server, '/infinite-stream');
                alarm(0);
                like $body, qr/0\r\n\r\n$/is, 'chunked eos';
            };
        }
    };

    subtest 'http2-client' => sub {
        plan skip_all => 'nghttp not found'
            unless prog_exists('nghttp');

        subtest 'oversize body' => sub {
            my ($server, $upstream) = $spawner->();
            my ($body_size, $info) = nghttp_get($server, '/content?size=100000&cl=80000');
            unlike $info, qr/RST_STREAM/is, 'no RST_STREAM';
            is $body_size, 80000, 'body size';
        };

        subtest 'incomplete body' => sub {
            my ($server, $upstream) = $spawner->();
            my ($body_size, $info) = nghttp_get($server, '/content?size=100000&cl=120000');
            like $info, qr/RST_STREAM/is, 'RST_STREAM';
            is $body_size, 100000, 'body size';
        };

        if ($chunked_enabled) {
            subtest 'upstream unexpectedly closed' => sub {
                my ($server, $upstream) = $spawner->();
                local $SIG{ALRM} = sub { kill 'KILL', $upstream->{pid} };
                alarm(1);
                my ($body_size, $info) = nghttp_get($server, '/infinite-stream');
                alarm(0);
                unlike $info, qr/RST_STREAM/is, 'no RST_STREAM';
            };
        }
    };
}

subtest 'proxy' => sub {
    my $spawner = sub {
        my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - proxy.reverse.url: http://127.0.0.1:$upstream->{port}/
EOT
        ($server, $upstream);
    };
    doit($spawner, 1);
};

subtest 'fastcgi' => sub {
    my $spawner = sub {
        my $upstream = create_upstream(qw(-s FCGI --manager=));
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - fastcgi.connect:
            port: $upstream->{port}
            type: tcp
EOT
        ($server, $upstream);
    };
    doit($spawner, 0);
};

subtest 'mruby-shortcut' => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};

    my $spawner = sub {
        my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - mruby.handler: |
            proc {|env|
              path = "#{env['PATH_INFO']}?#{env['QUERY_STRING']}"
              http_request("http://127.0.0.1:$upstream->{port}#{path}").join
            }
EOT
        ($server, $upstream);
    };
    doit($spawner, 1);
};

subtest 'mruby-no-shortcut' => sub {
    plan skip_all => 'mruby support is off'
        unless server_features()->{mruby};

    my $spawner = sub {
        my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - mruby.handler: |
            proc {|env|
              path = "#{env['PATH_INFO']}?#{env['QUERY_STRING']}"
              status, headers, body = http_request("http://127.0.0.1:$upstream->{port}#{path}").join
              [status, headers, Class.new do
                def initialize(body)
                  \@body = body
                end
                def each
                  \@body.each {|buf| yield buf }
                end
              end.new(body)]
            }
EOT
        ($server, $upstream);
    };
    doit($spawner, 1);
};

done_testing;
