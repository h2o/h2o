use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(check_port);
use File::Temp qw(tempfile);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub fetch {
    my $server = shift;
    my $host = shift;
    my $resp;
    if (defined($host)) {
        $resp = `curl --silent --resolve $host:$server->{port}:127.0.0.1 http://$host:$server->{port}/`;
    } else {
        $resp = `curl --silent --http1.0 --header Host: http://127.0.0.1:$server->{port}/`;
    }
    md5_hex($resp);
}

subtest "basic" => sub {
    # create config
    my ($global_port, $alternate_port) = empty_ports(2);
    my ($conffh, $conffn) = tempfile(UNLINK => 1);
    print $conffh <<"EOT";
listen:
  host: 127.0.0.1
  port: $global_port
hosts:
  "default:$global_port":
    paths:
      /:
        file.dir: examples/doc_root
  "alternate:$global_port":
    listen:
      host: 127.0.0.1
      port: $alternate_port
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT

    # start server
    my ($guard, $pid) = spawn_server(
        argv     => [ bindir() . "/h2o", "-c", $conffn ],
        is_ready => sub {
            check_port($global_port) && check_port($alternate_port);
        },
    );

    my $resp = `curl --silent --resolve default:$global_port:127.0.0.1 http://default:$global_port/`;
    is md5_hex($resp), md5_file("examples/doc_root/index.html"), "'host: default' against default port";

    $resp = `curl --silent --resolve alternate:$global_port:127.0.0.1 http://alternate:$global_port/`;
    is md5_hex($resp), md5_file("examples/doc_root.alternate/index.txt"), "'host: alternate' against default port";

    $resp = `curl --silent --resolve default:$alternate_port:127.0.0.1 http://default:$alternate_port/`;
    is md5_hex($resp), md5_file("examples/doc_root.alternate/index.txt"), "'host: default' against alternate port";

    $resp = `curl --silent --resolve alternate:$alternate_port:127.0.0.1 http://alternate:$alternate_port/`;
    is md5_hex($resp), md5_file("examples/doc_root.alternate/index.txt"), "'host: alternate' against alternate port";
};

subtest "wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
  "*.example.com:$port":
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    is fetch($server, "www.example.com"), md5_file("examples/doc_root.alternate/index.txt"), "www.example.com";
    is fetch($server, "xxx.example.com"), md5_file("examples/doc_root.alternate/index.txt"), "xxx.example.com";
    is fetch($server, "example.com"), md5_file("examples/doc_root/index.html"), "example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root/index.html"), "example.org";
};

subtest "default to first, without wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "example.com:$port":
    paths:
      /:
        file.dir: examples/doc_root
  "example.org:$port":
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    is fetch($server, "example.com"), md5_file("examples/doc_root/index.html"), "example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.alternate/index.txt"), "example.org";
    is fetch($server, undef), md5_file("examples/doc_root/index.html"), "no host header";
};

subtest "strict match, without wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root
  "example.org:$port":
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    is fetch($server, "example.com"), md5_file("examples/doc_root/index.html"), "example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.alternate/index.txt"), "example.org";
    is fetch($server, undef), md5_file("examples/doc_root.alternate/index.txt"), "no host header";
};

subtest "all strict match, without wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root
  "example.org:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root.alternate
EOT
    });

    is fetch($server, "example.com"), md5_file("examples/doc_root/index.html"), "example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.alternate/index.txt"), "example.org";
    is fetch($server, undef), md5_hex("not found"), "no host header";
};

subtest "default to first, with wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "www.example.com:$port":
    paths:
      /:
        file.dir: examples/doc_root
  "*.example.com:$port":
    paths:
      /:
        file.dir: examples/doc_root.alternate
  "*:$port":
    paths:
      /:
        file.dir: examples/doc_root.third
EOT
    });

    is fetch($server, "www.example.com"), md5_file("examples/doc_root/index.html"), "www.example.com";
    is fetch($server, "xxx.example.com"), md5_file("examples/doc_root.alternate/index.txt"), "xxx.example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.third/index.txt"), "example.org";
    is fetch($server, undef), md5_file("examples/doc_root/index.html"), "no host header";
};

subtest "strict match, with wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "www.example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root
  "*.example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root.alternate
  "*:$port":
    paths:
      /:
        file.dir: examples/doc_root.third
EOT
    });

    is fetch($server, "www.example.com"), md5_file("examples/doc_root/index.html"), "www.example.com";
    is fetch($server, "xxx.example.com"), md5_file("examples/doc_root.alternate/index.txt"), "xxx.example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.third/index.txt"), "example.org";
    is fetch($server, undef), md5_file("examples/doc_root.third/index.txt"), "no host header";
};

subtest "all strict match, with wildcard" => sub {
    my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
hosts:
  "www.example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root
  "*.example.com:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root.alternate
  "*:$port":
    strict-match: ON
    paths:
      /:
        file.dir: examples/doc_root.third
EOT
    });

    is fetch($server, "www.example.com"), md5_file("examples/doc_root/index.html"), "www.example.com";
    is fetch($server, "xxx.example.com"), md5_file("examples/doc_root.alternate/index.txt"), "xxx.example.com";
    is fetch($server, "example.org"), md5_file("examples/doc_root.third/index.txt"), "example.org";
    is fetch($server, undef), md5_hex("not found"), "no host header";
};

done_testing();
