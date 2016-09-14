use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::Builder;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

sub create_upstream {
    unlink "$tempdir/access_log";
    return spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
    access-log:
      path: $tempdir/access_log
      format: "%{ssl.session-reused}x"
EOT
}

sub doit {
    my ($conf, $scenario, $opts) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    $opts ||= +{};

    my $upstream = $opts->{upstream} || create_upstream();
    if (ref($conf) eq 'CODE') {
        $conf = $conf->($upstream);
    }
    my $server = spawn_h2o($conf);
    my $port = $server->{port};

    for my $s (@$scenario) {
        my $path = $s->{path} || '/';
        Time::HiRes::sleep($s->{interval}) if $s->{interval};
        my $res = `curl --silent --dump-header /dev/stderr http://127.0.0.1:@{[$server->{port}]}$path 2>&1 > /dev/null`;
        like $res, qr{^HTTP/1\.1 200 }, $s->{desc};
    }

    my @log = do {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open access_log:$!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };

    for my $i (0..scalar(@$scenario)-1) {
        my $s = $scenario->[$i];
        next unless defined($s->{expected});
        
        my $reused = $log[$i] + 0;
        is($reused, $s->{expected}, $s->{desc});
    }
};

subtest 'default' => sub {
    doit(sub {
        my ($upstream) = @_;
        return <<"EOC";
proxy.ssl.verify-peer: OFF
proxy.timeout.keepalive: 0
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
EOC
    }, [
        +{},
        +{ expected => 1 },
    ]);
};

subtest 'off' => sub {
    doit(sub {
        my ($upstream) = @_;
        return <<"EOC";
proxy.timeout.keepalive: 0
proxy.ssl.session-cache: OFF
hosts:
  default:
    paths:
      /:
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
EOC
    }, [
        +{},
        +{ expected => 0 },
    ]);
};

subtest 'lifetime' => sub {
    doit(sub {
        my ($upstream) = @_;
        return <<"EOC";
proxy.ssl.verify-peer: OFF
proxy.timeout.keepalive: 0
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
        proxy.ssl.session-cache:
          capacity: 4096
          lifetime: 2
EOC
    }, [
        +{},
        +{ interval => 1, expected => 1 },
        +{ interval => 2, expected => 0, desc => 'expire' },
    ]);
};

subtest 'config' => sub {
    doit(sub {
        my ($upstream) = @_;
        return <<"EOC";
proxy.ssl.verify-peer: OFF
proxy.timeout.keepalive: 0
hosts:
  default:
    proxy.ssl.session-cache: OFF
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
        proxy.ssl.session-cache: ON
      /sample.txt:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
        proxy.ssl.session-cache:
          capacity: 4096
          lifetime: 2
       
EOC
    }, [
        +{ path => '/' },
        +{ path => '/',           interval => 0, expected => 1, desc => 'reuse on second request to /' },
        +{ path => '/sample.txt', interval => 0, expected => 0, desc => 'not reuse on first request to /sample.txt' },
        +{ path => '/sample.txt', interval => 1, expected => 1, desc => 'reuse on second request to /sample.txt' },
        +{ path => '/sample.txt', interval => 2, expected => 0, desc => 'expire on third request to /sample.txt' },
    ]);
};

subtest 'reproxy' => sub {
    my $upstream = create_upstream();
    my $upstream_port = $upstream->{tls_port};
    my $app_port = empty_port();
    my $app_server = spawn_server(
        argv => [
            qw(
                plackup -s Starlet --max-workers=1 --port
            ),
            $app_port, "-e sub { [200, ['X-Reproxy-URL' => 'https://127.0.0.1:$upstream_port/'], []] }"
        ],
        is_ready => sub {
            check_port($app_port);
        },
    );

    doit(sub {
        return <<"EOC";
proxy.ssl.verify-peer: OFF
proxy.timeout.keepalive: 0
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$app_port
        reproxy: ON
EOC
    }, [
        +{},
        +{ expected => 1 },
    ], +{ upstream => $upstream });
};

subtest 'multiple-hosts' => sub {
    doit(sub {
        my ($upstream) = @_;
        return <<"EOC";
proxy.ssl.verify-peer: OFF
proxy.timeout.keepalive: 0
proxy.ssl.session-cache: ON
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
  example.com:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:@{[$upstream->{tls_port}]}
        proxy.ssl.verify-peer: ON
        proxy.ssl.session-cache: OFF
EOC
    }, [
        +{},
        +{ expected => 1 },
    ]);
};

done_testing();
