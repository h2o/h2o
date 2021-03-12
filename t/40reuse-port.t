use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => "ss not found"
    unless prog_exists("ss");

sub doit {
    my $reuseport = shift;
    my $server = spawn_h2o(<< "EOT");
num-threads: 4
tcp-reuseport: $reuseport
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT
    my $out = `ss -tlnp | grep -w 0.0.0.0:$server->{port} 2>&1`;
    print($out);
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
