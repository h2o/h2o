use strict;
use warnings;
use File::Temp qw(tempfile);
use Net::EmptyPort qw(check_port empty_port);
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

plan skip_all => "curl not found"
    unless prog_exists("curl");

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

subtest 'reproxy' => sub {
    my ($port1, $port2) = empty_ports(2, { host => "0.0.0.0" });
    my $path_conf = << "EOT";
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    doit($port1, $path_conf, $port2, $path_conf, sub {
        `curl --silent 'http://127.0.0.1:$port1/?resp:x-reproxy-url=http://127.0.0.1:$port2/'`;
    });
};

subtest 'location' => sub {
    my ($port1, $port2) = empty_ports(2, { host => "0.0.0.0" });
    my $path_conf1 = << "EOT";
        redirect:
          status: 302
          internal: YES
          url: http://127.0.0.1:$port2/
EOT
    my $path_conf2 = << "EOT";
        file.dir: t/assets/doc_root
EOT
    doit($port1, $path_conf1, $port2, $path_conf2, sub {
        `curl --silent --max-redirs 0 'http://127.0.0.1:$port1/'`;
    });
};

subtest 'errordoc' => sub {
    my ($port1, $port2) = empty_ports(2, { host => "0.0.0.0" });
    my $path_conf1 = << "EOT";
        file.dir: t/assets/doc_root
        error-doc:
          status: 404
          url: http://127.0.0.1:$port2/index.txt
EOT
    my $path_conf2 = << "EOT";
        file.dir: t/assets/doc_root
EOT
    doit($port1, $path_conf1, $port2, $path_conf2, sub {
        `curl --silent 'http://127.0.0.1:$port1/404'`;
    });
};

done_testing;

sub doit {
    my ($port1, $path_conf1, $port2, $path_conf2, $cb) = @_;
    (undef, my $access_log) = tempfile(UNLINK => 1);
    my $conf = << "EOT";
access-log: $access_log
reproxy: ON
hosts:
  "127.0.0.1:$port1":
    listen:
      host: 0.0.0.0
      port: $port1
    paths:
      "/":
$path_conf1
  "127.0.0.1:$port2":
    listen:
      host: 0.0.0.0
      port: $port2
    paths:
      "/":
$path_conf2
EOT
    my $server = _spawn_h2o_raw($conf, [$port1, $port2]);
    $cb->();

    my @log = do {
        open my $fh, '<', $access_log or die "failed to open log file: $!";
        <$fh>;
    };
    is scalar(@log), 1, 'redirected internally';
}

sub _spawn_h2o_raw {
    my ($conf, $ports) = @_;
    my @opts;

    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    print $conffh $conf;

    my ($guard, $pid) = spawn_server(
        argv     => [ bindir() . "/h2o", "-c", $conffn ],
        is_ready => sub {
            check_port($_) or return for @$ports;
            1;
        },
    );
    my $ret = {
        guard    => $guard,
        pid      => $pid,
        conf_file => $conffn,
    };
    return $ret;
}

