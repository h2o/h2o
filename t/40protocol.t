use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => +(stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt halfdome.jpg);

sub run_tests {
    my $extra_conf = shift;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
$extra_conf
EOT

    my $port = $server->{port};
    my $tls_port = $server->{tls_port};

    subtest 'curl' => sub {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            for my $file (sort keys %files) {
                my $content = `$curl --silent --show-error $proto://127.0.0.1:$port/$file`;
                is length($content), $files{$file}->{size}, "$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$file (md5)";
            }
        });
    };

    subtest 'nghttp' => sub {
        plan skip_all => 'nghttp not found'
            unless prog_exists('nghttp');
        my $doit = sub {
            my ($proto, $port) = @_;
            my $opt = $proto eq 'http' ? '-u' : '';
            for my $file (sort keys %files) {
                my $content = `nghttp $opt $proto://127.0.0.1:$port/$file`;
                is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
                is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
            }
            my $out = `nghttp -u -m 100 $proto://127.0.0.1:$port/index.txt`;
            is $out, "hello\n" x 100, "$proto://127.0.0.1/index.txt x 100 times";
        };
        $doit->('http', $port);
        subtest 'https' => sub {
            plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
                unless openssl_can_negotiate();
            $doit->('https', $tls_port);
        };
        subtest 'dtsu' => sub {
            plan skip_all => 'OpenSSL does not support protocol negotiation; it is too old'
                unless openssl_can_negotiate();
            for my $table_size (0, 1024) {
                my $content = `nghttp --header-table-size=$table_size https://127.0.0.1:$tls_port/index.txt`;
                is $content, "hello\n";
            }
        };
    };

    subtest 'ab' => sub {
        plan skip_all => 'ab not found'
            unless prog_exists('ab');
        ok(system("ab -c 10 -n 10000 -k http://127.0.0.1:$port/index.txt") == 0);
        ok(system("ab -f tls1 -c 10 -n 10000 -k https://127.0.0.1:$tls_port/index.txt") == 0);
    };
}

subtest 'default' => sub {
    run_tests(<< "EOT");
file.io_uring: OFF
EOT
};

subtest 'io_uring' => sub {
    plan skip_all => 'io_uring is not availble'
        unless server_features()->{io_uring};
    subtest 'file.io_uring=off' => sub {
        run_tests('file.io_uring: OFF');
    };
    for my $batch_size (qw(1 10)) {
        for my $spare_pipes (qw(0 10)) {
            subtest "(batch_size,spare_pipes)=($batch_size,$spare_pipes)" => sub {
                run_tests(join "\n", <<"EOT");
file.io_uring: ON
io_uring-batch-size: $batch_size
max-spare-pipes: $spare_pipes
EOT
            };
        }
    }
};

done_testing;
