use strict;
use warnings;
use File::Temp qw(tempfile);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $curl = "curl --silent --show-error --dump-header /dev/stderr";

subtest 'tag' => sub {
    subtest 'basic' => sub {
        my $included = temp_config_file(<< "EOT");
header.add: &marked "foo: FOO"
file.dir: @{[DOC_ROOT]}
EOT

        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /: !file $included
EOT

        my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/");
        like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
        like $stderr, qr{^foo: ?FOO\r$}im;
    };
    
    subtest 'multi-hop' => sub {
        my $included2 = temp_config_file(<< "EOT");
header.add: &marked "foo: FOO"
file.dir: @{[DOC_ROOT]}
EOT
        my $included1 = temp_config_file(<< "EOT");
!file $included2
EOT

        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /: !file $included1
EOT

        my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/");
        like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
        like $stderr, qr{^foo: ?FOO\r$}im;
    };
    
    subtest 'with-alias' => sub {
        my $included = temp_config_file(<< "EOT");
header.add: &marked "foo: FOO"
file.dir: @{[DOC_ROOT]}
EOT

        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /: !file $included
      /another:
        header.add: *marked
        file.dir: @{[DOC_ROOT]}
EOT

        subtest 'with_merge' => sub {
            my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/");
            like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
            like $stderr, qr{^foo: ?FOO\r$}im;
        };
    
        subtest 'with_alias' => sub {
            my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/another/");
            like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
            like $stderr, qr{^foo: ?FOO\r$}im;
        };
    };
    
    subtest 'with-merge' => sub {
        my $included2 = temp_config_file(<< "EOT");
header.add: "foo: FOO"
EOT
        my $included1 = temp_config_file(<< "EOT");
<<: !file $included2
header.append: "bar: BAR"
EOT

        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        <<: !file $included1
        file.dir: @{[ DOC_ROOT ]}
EOT

        my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/");
        like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
        like $stderr, qr{^foo: ?FOO\r$}im;
        like $stderr, qr{^bar: ?BAR\r$}im;
    };
    
    subtest 'env' => sub {
        my $spawn = sub {
            spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        header.add: !env FOO
        file.dir: @{[DOC_ROOT]}
EOT
        };
        subtest 'exist' => sub {
            local $ENV{FOO} = "hello: world";
            my $server = $spawn->();
            run_with_curl($server, sub {
                my ($proto, $port, $curl) = @_;
                my ($stderr, $stdout) = run_prog("$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/");
                like $stderr, qr{^hello: ?world\r$}im;
            });
        };
        subtest 'nonexist' => sub {
            local $@;
            delete local $ENV{FOO};
            my $server;
            eval {
                $server = $spawn->();
            };
            if ($@) {
                pass("failed to start");
            } else {
                sleep 1;
                my ($stderr, $stdout) = run_prog("curl --silent --dump-header /dev/stdout http://127.0.0.1:$server->{port}/");
                is $stdout, "", "server should be down due to misconfiguration";
            }
        };
    };
};

subtest 'stash' => sub {
    my $server = spawn_h2o(<< "EOT");
stash:
  headers: &headers
    header.add: "foo: FOO"
    header.add: "bar: BAR"
hosts:
  default:
    paths:
      /:
        <<: *headers
        file.dir: @{[DOC_ROOT]}
EOT

    my ($stderr, $stdout) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/");
    like $stderr, qr{^HTTP/[^ ]+ 200\s}s;
    like $stderr, qr{^foo: ?FOO\r$}im;
    like $stderr, qr{^bar: ?BAR\r$}im;
};

done_testing();

sub temp_config_file {
    my ($content) = @_;
    my ($fh, $fn) = tempfile(UNLINK => 1);
    print $fh $content;
    return $fn;
}
