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

    subtest 'http1' => sub {
        my @sts = nc_get($server, '/', 1);
        is scalar(@sts), 2, 'header and trailer';
    
        test_element($sts[0], 'connect', undef, undef);
        test_element($sts[0], 'header', undef, undef);
        test_element($sts[0], 'request_total', undef, undef);
        test_element($sts[0], 'process', 1000, 2000);
        test_element($sts[1], 'response', 1000, 2000);
        test_element($sts[1], 'total', 2000, 3000);
    };
    
    subtest 'http2' => sub {
        my @sts = nghttp_get($server, '/');
        is scalar(@sts), 2, 'header and trailer';
    
        test_element($sts[0], 'connect', undef, undef);
        test_element($sts[0], 'header', undef, undef);
        test_element($sts[0], 'request_total', undef, undef);
        test_element($sts[0], 'process', 1000, 2000);
        test_element($sts[1], 'response', 1000, 2000);
        test_element($sts[1], 'total', 2000, 3000);
    };
};

subtest 'disabled' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        - server-timing: on
        - file.dir: t/assets/doc_root
EOT

    subtest 'no te header' => sub {
        my @sts = nc_get($server, '/');
        is scalar(@sts), 0, 'no server timing';
    };

    subtest 'not chunked encoding' => sub {
        my @sts = nc_get($server, '/');
        is scalar(@sts), 0, 'no server timing';
    };
    
    subtest 'http2 is always ok' => sub {
        my @sts = nghttp_get($server, '/');
        is scalar(@sts), 2, 'header and trailer';
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
        my @sts = nc_get($server, '/');
        is scalar(@sts), 2, 'header and trailer';
    };
    
    subtest 'http2' => sub {
        my @sts = nghttp_get($server, '/');
        is scalar(@sts), 2, 'header and trailer';
    };
};

done_testing;

sub nc_get {
    my ($server, $path, $te_trailers) = @_;
    my $req = "GET $path HTTP/1.1\\r\\n";
    $req .= "TE: trailers\r\n" if $te_trailers;
    $req .= "\r\n";
    my $resp = `echo '$req' | nc 127.0.0.1 $server->{port}`;
    map { parse_server_timing($_) } ($resp =~ /^server-timing: (.+)$/mg);
}

sub nghttp_get {
    my ($server, $path) = @_; 
    my $out = `nghttp -vn 'https://127.0.0.1:$server->{tls_port}$path'`;
    map { parse_server_timing($_) } ($out =~ /recv \(stream_id=\d+\) server-timing: (.+)$/mg);
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
