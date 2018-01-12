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

# spawn server
my $server = spawn_h2o(<< "EOT");
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

# the logic should be same as the mruby handler
my $plack_app = sub {
    my $num_reqs = 0;
    sub {
        my $env = shift;
        ++$num_reqs;
        my $body = "count:$num_reqs";
        return [$env->{HTTP_EARLY_DATA} ? 425 : 200, ["content-length" => length $body], [$body]];
    };
}->();

subtest "http/1" => sub {
    my $fetch = sub {
        my ($path, $send_count) = @_;
        my $cmd = "exec @{[bindir]}/picotls/cli -s $tempdir/session -e 127.0.0.1 $server->{tls_port} > $tempdir/resp.txt";
        open my $fh, "|-", $cmd
            or die "failed to invoke command:$cmd:$!";
        autoflush $fh 1;
        for (my $i = 0; $i < $send_count; ++$i) {
            sleep 0.1
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
    my $do_test = sub {
        my $path = shift;
        unlink "$tempdir/session";
        my $resp = $fetch->($path, 1);
        like $resp, qr{^HTTP/[^ ]* 200 .*\r\n\r\ncount:1$}s;
        $resp = $fetch->($path, 1);
        like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:2$}s;
        $resp = $fetch->($path, 2);
        like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:3HTTP/[^ ]* 200 .*\r\n\r\ncount:4$}s;
    };
    subtest "proxy" => sub {
        my $guard = spawn_starlet();
        $do_test->("/proxy/");
    };
    subtest "fcgi" => sub {
        my $guard = spawn_fcgi();
        $do_test->("/fcgi/");
    };
    subtest "mruby" => sub {
        plan skip_all => "mruby is off"
            unless server_features()->{mruby};
        $do_test->("/mruby/");
    };
};

sub spawn_plack_server {
    my ($port, @options) = @_;
    my $upstream_pid = fork;
    die "fork failed:$!"
        unless defined $upstream_pid;
    if ($upstream_pid == 0) {
        my $runner = Plack::Runner->new;
        $runner->parse_options(@options, "--listen", "127.0.0.1:$port");
        $runner->run($plack_app);
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
    spawn_plack_server($upstream_port, qw(-s Starlet --max-workers=1 --access-log /dev/null));
}

sub spawn_fcgi {
    spawn_plack_server($upstream_port, qw(-s FCGI --nproc 1 --access-log /dev/null));
}

done_testing;
