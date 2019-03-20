use strict;
use warnings;
use feature qw/say/;
use Net::EmptyPort qw(check_port empty_port);
use Scope::Guard;
use Test::More;
use Time::HiRes;
use IO::Socket::INET;
use t::Util;

plan skip_all => "h2get not found"
    unless h2get_exists();


subtest 'upstream_h1' => sub {
    subtest 'no_wait_body' => sub {
        my $upstream_port = empty_port({ host => '0.0.0.0' });
        my $upstream = create_h1_upstream($upstream_port, 0);
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.timeout.keepalive: 100000
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

        my $output = run_with_h2get_simple($server, <<"EOS");
@{[do_read_method()]}
req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/" }
h2g.send_headers(req, 1, END_HEADERS)
h2g.send_data(1, 0, "a")
do_read(h2g, 100)
3.times {|n|
  sleep 1
  h2g.send_data(1, n == 3 ? END_STREAM : 0, "a" * 1024)
  break if do_read(h2g, 100)
}
EOS
        like $output, qr/HEADERS frame .+':status' => '200'/s;
        like $output, qr/RST_STREAM frame .+error_code => 0/s;
    };
    
    subtest 'wait_body' => sub {
        my $upstream_port = empty_port({ host => '0.0.0.0' });
        my $upstream = create_h1_upstream($upstream_port, 1);
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.timeout.keepalive: 100000
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
        my $output = run_with_h2get_simple($server, <<"EOS");
@{[do_read_method()]}
req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/",
    "content-length" => "#{1 + 1024 * 3}" # to avoid chunked encoding
}
h2g.send_headers(req, 1, END_HEADERS)
h2g.send_data(1, 0, "a")
do_read(h2g, 100)
3.times {|n|
  sleep 1
  h2g.send_data(1, n == 3 ? END_STREAM : 0, "a" * 1024)
  break if do_read(h2g, 100)
}
EOS
        like $output, qr/HEADERS frame .+':status' => '200'/s;
        unlike $output, qr/RST_STREAM frame/s;
    
        # issue second request to test that h2o closed the upstream connection
        # (otherwise framing error happens)
        `nghttp -v https://127.0.0.1:$server->{tls_port}`;
    
        $upstream->{kill}->();
        my $log = join('', readline($upstream->{stdout}));
        like $log, qr/accepted request 2/;
        like $log, qr/received @{[1 + 1024 * 3]} bytes/;
    };
};

done_testing;

sub create_h1_upstream {
    my ($upstream_port, $wait_body) = @_;

    my ($cout, $pin);
    pipe($pin, $cout);

    my $pid = fork;
    if ($pid) {
        close $cout;
        my $upstream; $upstream = +{
            pid => $pid,
            kill => sub {
                kill 'KILL', $pid if $pid;
                undef $pid;
            },
            guard => Scope::Guard->new(sub { $upstream->{kill}->() }),
            stdout => $pin,
        };
        return $upstream;
    }
    close $pin;
    open(STDOUT, '>&=', fileno($cout)) or die $!;
    my $server = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1
    );
    my $req = 0;
    while (my $client = $server->accept) {
        say "accepted request @{[++$req]}";
        my $buf = '';
        my $chunk;
        while ($client->sysread($chunk, 1) > 0) {
            $buf .= $chunk;
            if ($buf =~ /\r\n\r\n$/) {
                my $content = "hello";
                $client->syswrite(join("\r\n", (
                    "HTTP/1.1 200 OK",
                    "Content-Length: @{[length($content)]}",
                    "", ""
                )) . $content);
                $client->flush;
                last;
            }
        }
        if ($wait_body) {
            $buf = '';
            while ($client->sysread($chunk, 1024) > 0) {
                Time::HiRes::sleep(0.0001);
                $buf .= $chunk;
            }
            say "received @{[length($buf)]} bytes";
        }
        sleep 1;
        $client->close;
    }
    $server->close;
}

sub do_read_method {
    return <<'EOS';
def do_read(h2g, timeout)
    while true
        f = h2g.read(timeout)
        return false if f == nil
        puts f.to_s
        if f.type == "DATA" && f.len > 0
            h2g.send_window_update(0, f.len)
            h2g.send_window_update(f.stream_id, f.len)
        end
        if (f.type == "DATA" || f.type == "HEADERS") && f.is_end_stream
            return true
        elsif f.type == "RST_STREAM" || f.type == "GOAWAY"
            return true
        end
    end
end
EOS
}

