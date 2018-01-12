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

# spawn upstream
my $upstream_port = empty_port();

# spawn upstream server
my $upstream_pid = fork;
die "fork failed:$!"
    unless defined $upstream_pid;
if ($upstream_pid == 0) {
    my $runner = Plack::Runner->new;
    $runner->parse_options(qw(-s Starlet --max-workers=1 --access-log /dev/null --listen), "127.0.0.1:$upstream_port");
    $runner->run(sub {
        my $num_reqs = 0;
        sub {
            my $env = shift;
            ++$num_reqs;
            my $body = "count:$num_reqs";
            return [$env->{HTTP_EARLY_DATA} ? 425 : 200, ["content-length" => length $body], [$body]];
        };
    }->());
    exit 0;
}
my $upstream_guard = scope_guard(sub {
    kill 'TERM', $upstream_pid;
    while (waitpid($upstream_pid, 0) != $upstream_pid) {}
});

# spawn server
my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

sub send_request {
    my $send_count = shift;
    my $cmd = "exec @{[bindir]}/picotls/cli -s $tempdir/session -e 127.0.0.1 $server->{tls_port} > $tempdir/resp.txt";
    open my $fh, "|-", $cmd
        or die "failed to invoke command:$cmd:$!";
    autoflush $fh 1;
    for (my $i = 0; $i < $send_count; ++$i) {
        sleep 0.1
            if $i != 0;
        print $fh <<"EOT";
GET / HTTP/1.1\r
Host: 127.0.0.1:$server->{tls_port}\r
Connection: @{[$i + 1 == $send_count ? "close" : "keep-alive"]}\r
\r
EOT
    }
    close $fh;
    open my $fh, "<", "$tempdir/resp.txt"
        or die "failed to open file:$tempdir/resp.txt:$!";
    do { local $/; <$fh> };
}

subtest "http/1" => sub {
    my $resp = send_request(1);
    like $resp, qr{^HTTP/[^ ]* 200 .*\r\n\r\ncount:1$}s;
    $resp = send_request(1);
    like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:2$}s;
    $resp = send_request(2);
    like $resp, qr{^HTTP/[^ ]* 425 .*\r\n\r\ncount:3HTTP/[^ ]* 200 .*\r\n\r\ncount:4$}s;
};

done_testing;
