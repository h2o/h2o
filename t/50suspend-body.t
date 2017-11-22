use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(alarm);
use t::Util;


sub nc_get {
    my ($server, $path) = @_;
    my $resp = `echo 'GET $path HTTP/1.1\\r\\n\\r\\n' | nc -w 1 127.0.0.1 $server->{port}`;
    my ($headers) = split(/\r\n\r\n/, $resp, 2);
    (length($headers || ''), $headers);
}

sub nghttp_get {
    my ($server, $path) = @_; 
    my $out = `nghttp -vn -t 1 'https://127.0.0.1:$server->{tls_port}$path'`;
    my $headers_size = 0;
    while ($out =~ /recv HEADERS frame <length=(\d+)/g) {
        $headers_size += $1;
    }
    ($headers_size, $out);
}

sub doit {
    my ($server) = @_;
    my $headers_size;

    ($headers_size) = nc_get($server, '/suspend-body');
    isnt $headers_size, 0, 'http/1';

    ($headers_size) = nghttp_get($server, '/suspend-body');
    isnt $headers_size, 0, 'http/2';
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

subtest 'proxy' => sub {
    my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - proxy.reverse.url: http://127.0.0.1:$upstream->{port}/
EOT
    doit($server);
};

subtest 'fastcgi' => sub {
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
    doit($server);
};

subtest 'mruby-http-chunked' => sub {
    my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - mruby.handler: |
            proc {|env|
              http_request("http://127.0.0.1:$upstream->{port}#{env['PATH_INFO']}").join
            }
EOT
    doit($server);
};

subtest 'mruby-callback-chunked' => sub {
    my $upstream = create_upstream(qw(-s Starlet --max-workers 0));
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - mruby.handler: |
            proc {|env|
              resp = http_request("http://127.0.0.1:$upstream->{port}#{env['PATH_INFO']}").join
              [resp[0], resp[1], Class.new do
                def initialize(body)
                  \@body = body
                end
                def each
                  \@body.each {|chunk| yield chunk }
                end
              end.new(resp[2])]
            }
EOT
    doit($server);
};

done_testing;
