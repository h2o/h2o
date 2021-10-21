use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "ss not found"
    unless prog_exists("ss");

sub doit {
    my $reuseport = shift;
    my ($port) = empty_ports(1, { host => "0.0.0.0" });
    my $server = spawn_h2o_raw(<< "EOT", [$port]);
tcp-reuseport: $reuseport
listen:
  host: 0.0.0.0
  port: $port
num-threads: 4
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT
    my $out = `ss -tlnp | grep ":$port" 2>&1`;
    if ($reuseport eq 'ON') {
        my @lines = split(/\n/, $out);
        is scalar(@lines), 4, "Found 4 listeners";
    } else {
        my @lines = split(/\n/, $out);
        is scalar(@lines), 1, "Found 1 listener";
        $out =~ /.*users:(.*)$/;
        my $u = $1;
        my @users = split(/,/, $u);
        is scalar(@users), 12, "Found 4 threads using the same queue, different fds";
    }
}

doit('ON');
doit('OFF');
done_testing;
