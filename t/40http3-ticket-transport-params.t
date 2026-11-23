use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

# checks that 0-RTT is rejected, while the session is still resumed, when the server advertises smaller limits than the one that
# issued the ticket

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

# spawns a server sharing the ticket keys with the others
sub spawn {
    my ($name, $conf) = @_;
    my $server = spawn_h2o(<< "EOT");
$conf
access-log:
  path: $tempdir/$name.log
  format: "%s %{ssl.session-reused}x %{http3.quic-stats}x"
ssl-session-resumption:
  mode: ticket
  ticket-store: file
  ticket-file: t/40session-ticket/forever_ticket.yaml
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    $server->{log} = "$tempdir/$name.log";
    $server;
}

# obtains a ticket from `$issuer`, then uses it to fetch from `$server`; returns the access log entry of the latter
sub resume {
    my ($name, $issuer, $server) = @_;
    for my $s ($issuer, $server) {
        my $resp = `$client_prog -k -3 100 -s $tempdir/$name.session https://127.0.0.1:$s->{quic_port}/ 2>&1`;
        is $?, 0, "fetch" or diag $resp;
    }
    for (1 .. 50) {
        my $log = do { local @ARGV = ($server->{log}); local $/; <> } // '';
        return $log if $log ne '';
        sleep 0.1;
    }
    fail "no access log entry";
    '';
}

my $issuer = spawn("issuer", "");

subtest "same settings" => sub {
    my $log = resume("same", $issuer, spawn("same", ""));
    like $log, qr/^200 1 .*num-packets\.zero-rtt-received=[1-9]/, "resumed with 0-RTT";
};

subtest "lower http3-input-window-size" => sub {
    my $log = resume("lower", $issuer, spawn("lower", "http3-input-window-size: 2097152"));
    like $log, qr/^200 1 .*num-packets\.zero-rtt-received=0[^0-9]/, "resumed without 0-RTT";
};

done_testing;
