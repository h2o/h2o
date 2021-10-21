use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Scope::Guard qw(scope_guard);
use Test::Requires qw(Plack::Runner Starlet);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $upstream_port = empty_port();

subtest "http/1" => sub {
    my $fetch = sub {
        my ($server, $path, $send_count) = @_;
        my $cmd = "exec @{[bindir]}/picotls/cli -I -s $tempdir/session -e 127.0.0.1 $server->{tls_port} > $tempdir/resp.txt";
        open my $fh, "|-", $cmd
            or die "failed to invoke command:$cmd:$!";
        autoflush $fh 1;
        for (my $i = 0; $i < $send_count; ++$i) {
            sleep 0.5
                if $i != 0;
            print $fh <<"EOT";
GET $path HTTP/1.1\r
Host: 127.0.0.1:$server->{tls_port}\r
Connection: @{[$i + 1 == $send_count ? "close" : "keep-alive"]}\r
\r
EOT
        }
        close $fh;
        open $fh, "<", "$tempdir/resp.txt"
            or die "failed to open file:$tempdir/resp.txt:$!";
        do { local $/; <$fh> };
    };
    run_tests(sub {
        my ($server, $path) = @_;
        my $resp = $fetch->($server, $path, 1);
        like $resp, qr{^HTTP/[^ ]* 200 .*\r\n\r\ncount:1$}s;
        $resp = $fetch->($server, $path, 1);
        like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:2$}s;
        $resp = $fetch->($server, $path, 2);
        like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:3HTTP/[^ ]* 200 .*\r\n\r\ncount:4$}s;
    });
};

subtest "http/2" => sub {
    my $fetch = sub {
        my ($server, $path) = @_;
        my $cmd = "exec @{[bindir]}/picotls/cli -I -s $tempdir/session -e 127.0.0.1 $server->{tls_port} > $tempdir/resp.txt";
        my $pid = open my $child_in, "|-", $cmd
            or die "failed to invoke command:$cmd:$!";
        autoflush $child_in 1;
        # send request
        my $hpack_str = sub { chr(length $_[0]) . $_[0] };
        my $hpack_hdr = sub { "\x10" . $hpack_str->($_[0]) . $hpack_str->($_[1]) };
        my $hpack = join("",
            $hpack_hdr->(":method", "GET"),
            $hpack_hdr->(":scheme", "https"),
            $hpack_hdr->(":authority", "127.0.0.1"),
            $hpack_hdr->(":path", $path),
        );
        syswrite $child_in, join '', (
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",                             # preface
            "\x00\x00\x00\x04\x00\x00\x00\x00\x00",                         # SETTINGS
            "\x00\x00@{[chr length $hpack]}\x01\x05\x00\x00\x00\x01$hpack", # HEADERS
        );

        while (waitpid($pid, 0) != $pid) {}

        open my $fh, "<", "$tempdir/resp.txt"
            or die "failed to open file:$tempdir/resp.txt:$!";
        do { local $/; <$fh> };
    };
    run_tests(sub {
        my ($server, $path) = @_;
        my $resp = $fetch->($server, $path);
        # HEADERS for stream zero starting with :status:200 followed by DATA frame carrying the expected content
        like $resp, qr{\x01\x04\x00\x00\x00\x01\x88.*\x00[\x00\x01]\x00\x00\x00\x01count:1}is;
        $resp = $fetch->($server, $path);
        like $resp, qr{\x01\x04\x00\x00\x00\x01\x88.*\x00[\x00\x01]\x00\x00\x00\x01count:3}is;
    });
};

sub run_tests {
    my $do_test = shift;
    # spawn server
    my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 1
num-threads: 1
hosts:
  default:
    paths:
      /proxy/:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
      /fcgi/:
        fastcgi.connect:
          host: 127.0.0.1
          port: $upstream_port
          type: tcp
@{[server_features()->{mruby} ? << "EOT2" : ""
      /mruby/:
        mruby.handler: |
          num_reqs = 0
          Proc.new do |req|
            num_reqs += 1
            [req["HTTP_EARLY_DATA"] ? 425 : 200, {}, ["count:#{num_reqs}"]]
          end
EOT2
]}
EOT
    # give some time to h2o to setup the session ticket encryption key
    sleep 1;
    # run tests
    subtest "proxy" => sub {
        for my $sleep (0, 1) {
            subtest "sleep=$sleep" => sub {
                unlink "$tempdir/session";
                my $guard = spawn_starlet($sleep);
                $do_test->($server, "/proxy/");
            };
        }
    };
    subtest "fcgi" => sub {
        for my $sleep (0, 1) {
            subtest "sleep=$sleep" => sub {
                unlink "$tempdir/session";
                my $guard = spawn_fcgi($sleep);
                $do_test->($server, "/fcgi/");
            };
        }
    };
    subtest "mruby" => sub {
        unlink "$tempdir/session";
        plan skip_all => "mruby is off"
            unless server_features()->{mruby};
        $do_test->($server, "/mruby/");
    };
}


sub spawn_plack_server {
    my ($sleep_secs, $port, @options) = @_;
    # the logic should be same as the mruby handler
    my $app = sub {
        my $num_reqs = 0;
        sub {
            my $env = shift;
            sleep $sleep_secs;
            ++$num_reqs;
            my $body = "count:$num_reqs";
            return [$env->{HTTP_EARLY_DATA} ? 425 : 200, ["content-length" => length $body], [$body]];
        };
    }->();

    my $upstream_pid = fork;
    die "fork failed:$!"
        unless defined $upstream_pid;
    if ($upstream_pid == 0) {
        my $runner = Plack::Runner->new;
        $runner->parse_options(@options, "--listen", "127.0.0.1:$port");
        $runner->run($app);
        exit 0;
    }
    while (!check_port($port)) {
        sleep 0.1;
    }
    scope_guard(sub {
        kill 'TERM', $upstream_pid;
        while (waitpid($upstream_pid, 0) != $upstream_pid) {}
    });
}

sub spawn_starlet {
    spawn_plack_server(@_, $upstream_port, qw(-s Starlet --max-workers=1 --access-log /dev/null));
}

sub spawn_fcgi {
    spawn_plack_server(@_, $upstream_port, qw(-s FCGI --nproc 1 --access-log /dev/null));
}

done_testing;
