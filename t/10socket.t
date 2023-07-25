use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use Test::More;
use t::Util;

my $TEST_FILE = "t/assets/doc_root/halfdome.jpg";
my $TEST_FILE_SIZE = (stat $TEST_FILE)[7];
my $TEST_FILE_MD5 = `openssl md5 < $TEST_FILE`;

my $server_port = empty_port();

sub doit {
    my ($progname, $is_ssl) = @_;

    # create listener
    my $listener;
    if ($is_ssl) {
        $listener = IO::Socket::SSL->new(
            LocalAddr     => "0.0.0.0",
            LocalPort     => $server_port,
            Listen        => 5,
            ReuseAddr     => 1,
            SSL_cert_file => "examples/h2o/server.crt",
            SSL_key_file  => "examples/h2o/server.key",
        ) or die "failed to listen to port:$server_port";
    } else {
        $listener = IO::Socket::INET->new(
            LocalAddr => "0.0.0.0",
            LocalPort => $server_port,
            Listen    => 5,
            ReuseAddr => 1,
        ) or die "failed to listen to port:$server_port";
    }

    # spawn the echo server
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        while (my $sock = $listener->accept) {
            while (IO::Select->new($sock)->can_read(1)) {
                $sock->sysread(my $buf, 65536)
                    or last;
                $sock->syswrite($buf) == length($buf)
                    or die "syswrite failed:$!";
            }
            close $sock;
        }
        exit(0);
    }

    # close the listener not that we've forked
    close $listener;

    # send large object, receive echo
    my $cmd = "$progname @{[$is_ssl ? '--tls --insecure': '']} -s localhost.examp1e.net $server_port < $TEST_FILE | openssl md5";
    my $output = `$cmd`;
    is $output, $TEST_FILE_MD5;

    # kill the server
    kill 'KILL', $pid;
    while (waitpid($pid, 0) != $pid) {}
}

for my $backend (qw(evloop libuv)) {
    subtest $backend => sub {
        my $prog = bindir() . "/examples-socket-client-$backend";
        plan skip_all => "$prog not found"
            unless -x $prog;

        subtest "cleartext" => sub {
            doit($prog, undef);
        };
        subtest "ssl" => sub {
            doit($prog, 1);
        };
    }
};

done_testing;
