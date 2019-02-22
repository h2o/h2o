use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use Test::Exception;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

subtest "gets" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /basic:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            chunks = []
            chunks << is.gets
            chunks << is.gets
            if is.gets
              chunks << 'garbage found'
            end
            [200, {}, [chunks.join(',')]]
          }
      /other-separator:
        mruby.handler: |
          proc {|env|
            $/ = '23'
            is = env['rack.input']
            chunks = []
            chunks << is.gets
            chunks << is.gets
            if is.gets
              chunks << 'garbage found'
            end
            [200, {}, [chunks.join(',')]]
          }
EOT
    my $curl_opts = "--silent --dump-header /dev/stderr -X POST --data-binary '123\n45'";

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/basic");
        is $stdout, "123\n,45";
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/other-separator");
        is $stdout, "123,\n45";
    });

};

subtest "rewind" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /no-rewind:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            chunks = []
            chunks << is.read(2)
            chunks << is.read
            [200, {}, chunks]
          }
      /rewind:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            chunks = []
            chunks << is.read(2)
            is.rewind
            chunks << is.read
            [200, {}, chunks]
          }
      /not-rewindable-error:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            is.rewindable = false
            begin
              is.rewind
              [200, {}, []]
            rescue IOError => e
              [503, {}, [e.message]]
            end
          }
      /true-to-false:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            chunks = []
            chunks << is.read(2)
            is.rewindable = false
            chunks << is.read
            [200, {}, chunks]
          }
      /false-to-true:
        mruby.handler: |
          proc {|env|
            is = env['rack.input']
            chunks = []
            is.rewindable = false
            chunks << is.read(2)
            is.rewindable = true
            chunks << is.read(2)
            is.rewind
            chunks << is.read
            [200, {}, chunks]
          }
EOT
    my $curl_opts = '--silent --dump-header /dev/stderr -X POST --data-binary "12345"';

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/no-rewind");
        is $stdout, '12345';
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/rewind");
        is $stdout, '1212345';
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/not-rewindable-error");
        like $stderr, qr{^HTTP\/[\d\.]+ 503 }s;
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/true-to-false");
        is $stdout, '12345';
    });

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl $curl_opts $proto://127.0.0.1:$port/false-to-true");
        is $stdout, '1234345';
    });
};

done_testing();
