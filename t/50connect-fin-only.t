use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use IPC::Open3;
use IO::Select;
use Test::More;
use Time::HiRes qw(sleep time);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.connect:
          - "+127.0.0.1:*"
        proxy.timeout.io: 30000
EOT

for my $proto (
    ["h1", "http",  $server->{port},      ""],
    ["h2", "https", $server->{tls_port},  "-2 100"],
    ["h3", "https", $server->{quic_port}, "-3 100"],
) {
    my ($name, $scheme, $port, $opts) = @$proto;
    subtest $name => sub {
        my ($origin_pid, $origin_port, $result_file) = spawn_origin();
        my ($client_stdin, $client_stdout);
        my $client_pid = open3(
            $client_stdin,
            $client_stdout,
            undef,
            "exec $client_prog -k $opts -m CONNECT -x $scheme://127.0.0.1:$port 127.0.0.1:$origin_port 2>&1"
        );
        die "failed to spawn h2o-httpclient"
            unless $client_pid > 0;

        my $headers = read_until_blocked($client_stdout);
        like $headers, qr{^HTTP/\S+ 200.*\n\n$}s, "CONNECT established";

        is syswrite($client_stdin, "hello"), 5, "sent tunnel bytes";
        sleep 1;
        close $client_stdin;

        my $start = time;
        for (my $i = 0; $i != 8 && !-e $result_file; ++$i) {
            sleep 0.25;
        }
        ok -e $result_file, "origin observed EOF";
        cmp_ok time - $start, "<", 3, "EOF was delivered before idle timeout";
        if (-e $result_file) {
            open my $fh, "<", $result_file
                or die "failed to open result file:$!";
            my $body = do { local $/; <$fh> };
            is $body, "hello", "origin received exactly the tunnel bytes";
        }

        kill 'KILL', $client_pid;
        waitpid $client_pid, 0;
        kill 'KILL', $origin_pid;
        waitpid $origin_pid, 0;
    };
}

done_testing;

sub spawn_origin {
    my $listener = IO::Socket::INET->new(
        Listen    => 1,
        LocalAddr => "127.0.0.1:0",
        Proto     => "tcp",
    ) or die "failed to open listener:$!";
    my $origin_port = $listener->sockport;
    my $result_file = "$tempdir/origin-$origin_port.txt";
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        my $sock = $listener->accept
            or die "accept failed:$!";
        my $body = "";
        while (1) {
            my $r = sysread $sock, my $buf, 8192;
            die "read failed:$!"
                unless defined $r;
            last if $r == 0;
            $body .= $buf;
        }
        open my $fh, ">", $result_file
            or die "failed to open result file:$!";
        print $fh $body;
        close $fh;
        exit 0;
    }
    undef $listener;
    return ($pid, $origin_port, $result_file);
}

sub read_until_blocked {
    my $fh = shift;
    my $buf = "";
    while (IO::Select->new([ $fh ])->can_read(0.5)) {
        my $r = sysread $fh, my $chunk, 8192;
        last unless defined $r && $r > 0;
        $buf .= $chunk;
    }
    $buf;
}
