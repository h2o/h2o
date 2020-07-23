use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes;
use t::Util;


subtest 'basic' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - server-timing: on
        - mruby.handler: |
            proc {|env|
              sleep 1
              [200, {}, Class.new do
                def each
                  yield 'hello'
                  sleep 1
                  yield 'world!'
                end
              end.new]
            }
EOT

    my $check = sub {
        my @sts = @_;
        # durations might be less than the slept amount because h2o's timestamps are updated at each eventloop
        # so we have to introduce 100ms lower buffer (i.e. 900ms, 1900ms)
        test_element($sts[0], 'connect', undef, undef);
        test_element($sts[0], 'request-header', undef, undef);
        test_element($sts[0], 'request-total', undef, undef);
        test_element($sts[0], 'process', 900, 1100);
        test_element($sts[1], 'response', 900, 1100);
        test_element($sts[1], 'total', 1900, 2100);
    };

    subtest 'http1' => sub {
        my ($sts) = nc_get($server, '/');
        is scalar(@$sts), 2, 'header and trailer';
        ok defined($sts->[0]->{connect});
        ok defined($sts->[1]->{total});
        $check->(@$sts);
    
    };
    
    subtest 'http2' => sub {
        my ($sts) = nghttp_get($server, '/');
        is scalar(@$sts), 2, 'header and trailer';
        ok defined($sts->[0]->{connect});
        ok defined($sts->[1]->{total});
        $check->(@$sts);
    };
};

subtest 'disabled trailer' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - server-timing: on
        - file.dir: t/assets/doc_root
EOT

    subtest 'not chunked encoding' => sub {
        my ($sts) = nc_get($server, '/');
        is scalar(@$sts), 1, 'no server timing trailer';
        ok defined($sts->[0]->{connect});
    };
    
    subtest 'http2 is always ok' => sub {
        my ($sts) = nghttp_get($server, '/');
        is scalar(@$sts), 2, 'header and trailer';
        ok defined($sts->[0]->{connect});
        ok defined($sts->[1]->{total});
    };
};

subtest 'enforce' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - server-timing: enforce
        - file.dir: t/assets/doc_root
EOT

    subtest 'http1' => sub {
        my ($sts) = nc_get($server, '/');
        is scalar(@$sts), 2, 'header and trailer';
    };
    
    subtest 'http2' => sub {
        my ($sts) = nghttp_get($server, '/');
        is scalar(@$sts), 2, 'header and trailer';
    };
};

subtest 'broken trailers when status is other than 200 (#1790)' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - server-timing: ON
        - mruby.handler: |
            proc {|env|
              [404, {}, Class.new do
                def each
                  yield 'not found'
                end
              end.new]
            }
EOT
    my ($sts, $raw) = nc_get($server, '/');
    is scalar(@$sts), 2;
    ok defined($sts->[0]->{connect});
    ok defined($sts->[1]->{total});
    unlike $raw, qr{not foundserver-timing}i;
};

done_testing;

sub nc_get {
    my ($server, $path) = @_;
    my $req = "GET $path HTTP/1.1\r\n\r\n";
    my $resp = `echo '$req' | nc 127.0.0.1 $server->{port}`;
    ([map { parse_server_timing($_) } ($resp =~ /^server-timing: (.+)$/mg)], $resp);
}

sub nghttp_get {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my ($server, $path) = @_; 
    my $out = `nghttp -vn 'https://127.0.0.1:$server->{tls_port}$path'`;
    ([map { parse_server_timing($_) } ($out =~ /recv \(stream_id=\d+\) server-timing: (.+)$/mg)], $out);
}

sub parse_server_timing {
    my ($str) = @_;
    +{ map { split (/; dur=/, $_, 2) } split(/, /, $str) };
}

sub test_element {
    my ($st, $name, $lower, $upper) = @_;
    subtest $name => sub {
        my $value = $st->{$name};
        ok defined $value;
        cmp_ok $value, '>=', $lower, "lower bound" if defined $lower;
        cmp_ok $value, '<',  $upper, "upper bound" if defined $upper;
    };
}
