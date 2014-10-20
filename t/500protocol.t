use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(empty_port);
use Proc::Wait3 qw(wait3);
use Scope::Guard qw(scope_guard);
use Test::More;

my $port = empty_port();

# spawn the server
my $pid = fork;
die "fork failed:$!"
    unless defined $pid;
if ($pid == 0) {
    # write configuration and start h2o
    my ($conffh, $conffn) = tempfile();
    print $conffh <<"EOT";
listen: $port
files:
  /: t/protocol/docroot
mime-types:
  txt: text/plain
  jpg: image/jpeg
EOT
    exec "./h2o", "-c", $conffn;
    die "failed to spawn h2o:$!";
}
my $guard = scope_guard(sub {
    kill 'TERM', $pid;
});

sleep 1;
die "server died, abort"
    if defined wait3(0);

subtest 'curl' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');
    my $content = `curl http://127.0.0.1:$port/index.txt 2> /dev/null`;
    ok($content eq "hello\n");
};

subtest 'ab' => sub {
    plan skip_all => 'ab not found'
        unless prog_exists('ab');
    ok(system("ab -c 10 -n 10000 -k http://127.0.0.1:$port/index.txt") == 0);
};

subtest 'nghttp' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $out = `nghttp -u -m 100 http://127.0.0.1:$port/index.txt 2> /dev/null`;
    ok $? == 0;
    is $out, "hello\n" x 100;
};

done_testing;

sub prog_exists {
    my $prog = shift;
    system("which $prog > /dev/null 2>&1") == 0;
}
