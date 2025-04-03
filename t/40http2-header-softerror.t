use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::IP;
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
access-log:
  format: '\%s'
  path: $tempdir/access_log
EOT

sleep 0.5;

open my $logfh, "<", "$tempdir/access_log"
    or die "failed to open $tempdir/access_log:$!";

subtest "empty-header-name" => sub {
    submit("GET / HTTP/1.0\r\n\r\n");
    sleep 0.1;
    is get_status(), 200;
    submit("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00=\x01\x05\x00\x00\x00\x01\x00\n:authority\tlocalhost\x00\x05:path\x01/\x00\x07:method\x03GET\x00\x07:scheme\x04http\x00\x00\x00");
    sleep 0.1;
    is get_status(), 400;
};

subtest "header-values-with-surronding-space" => sub {
    submit("GET / HTTP/1.0\r\n\r\n");
    sleep 0.1;
    is get_status(), 200;
    submit("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00E\x01\x05\x00\x00\x00\x01\x00\n:authority\tlocalhost\x00\x05:path\x01/\x00\x07:method\x03GET\x00\x07:scheme\x04http\x00\x05test1\x03\ta\t");
    sleep 0.1;
    is get_status(), 400;
};

undef $server;

done_testing;

# connect, send (broken) request, read something
sub submit {
    my $msg = shift;

    my $sock = IO::Socket::IP->new(
        PeerHost => "127.0.0.1",
        PeerPort => $server->{port},
        Type     => SOCK_STREAM,
    ) or die "failed to connect to 127.0.0.1:@{[$server->{port}]}:$!";
    $sock->syswrite($msg);
    $sock->sysread(my $resp, 1024);
}

# read status from access log
sub get_status {
    my $line = <$logfh>;
    chomp $line;
    $line;
}
