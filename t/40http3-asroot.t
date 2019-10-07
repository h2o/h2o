use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port wait_port);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

run_as_root();

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

plan skip_all => 'dtrace not found'
    unless prog_exists('dtrace');
plan skip_all => 'bpftrace is not supported'
    if $^O eq 'linux';
plan skip_all => 'unbuffer not found'
    unless prog_exists('unbuffer');

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

subtest 'retry' => sub {
    subtest 'off' => sub {
        my $server = spawn_retry_server('OFF');
        my @lines = fetch("https://127.0.0.1:$quic_port");
        like join("", @lines), qr{^HTTP/3 200}m;
        unlike join("", @lines), qr{^first-byte: f}m;
    };
    subtest 'on' => sub {
        my $server = spawn_retry_server('ON');
        my @lines = fetch("https://127.0.0.1:$quic_port");
        like join("", @lines), qr{^HTTP/3 200}m;
        like +(grep {/^first-byte: /} @lines)[0], qr/^first-byte: f[0-9a-f]$/m;
    };
};

done_testing;

sub spawn_retry_server {
    my $boolflag = shift;
    my $server = spawn_h2o(<< "EOT");
listen:
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  quic:
    retry: $boolflag
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
    wait_port({port => $quic_port, proto => 'udp'});
    $server;
}

sub fetch {
    my $progargs = shift;
    pipe my $readfh, my $writefh
        or die "pipe failed:$!";
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # child process
        close $readfh;
        open STDOUT, ">&", $writefh
            or die "failed to redirect stdout to pipe:$!";
        open STDERR, ">&", $writefh
            or die "failed to redirect stderr to pipe:$!";
        exec qw(dtrace -q -c), "$client_prog -3 $progargs", "-n", <<'EOT';
quicly$target:::receive {
    bytes = (uint8_t *)copyin(arg3, arg4);
    printf("first-byte: %02x\n", bytes[0]);
}
EOT
        die "falied to exec dtrace:$!";
    }
    # parent process
    close $writefh;
    my @lines = <$readfh>;
    while (wait() != $pid) {}
    @lines;
}
