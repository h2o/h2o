use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "basic" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        - mruby.handler: |
            require 'prometheus.rb'
            H2O::Prometheus.new(H2O.next)
        - status: ON
EOT
    my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
    like $stderr, qr{^HTTP\/1.\d 200 }s or return;
    my $metrics = parse_output($stdout) or return;

    # don't care about the actual parsing result for now
    pass;
};

done_testing();

sub parse_output {
    my ($out) = @_;
    my @ret;
    my @lines = split(/\n/, $out);
    while (my ($helpline, $typeline) = splice(@lines, 0, 2)) {
        my ($name, $type, $version, $value);
        if ($helpline =~ /^# HELP (\w+)/) {
            $name = $1;
        } else {
            fail("invalid helpline: $helpline");
            return;
        }
        if ($typeline =~ /^# TYPE $name (.+)$/) {
            $type = $1;
        } else {
            fail("invalid typeline: $typeline");
            return;
        }
        # there can be multiple valuelines per typeline
        foreach my $valueline (@lines) {
            last unless ($valueline =~ /^$name\{version="(.*)"\} (.*)$/);
            push(@ret, +{
                name => $name,
                type => $type,
                version => $1,
                value => $2,
            });
            shift @lines;
        }
    }
    return \@ret;
}
