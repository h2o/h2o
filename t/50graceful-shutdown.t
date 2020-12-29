use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes;
use t::Util;

# 1. send headers
# 2. 1st goaway
# 3. send data (with END_STREAM flag)
# 4. 2nd goaway
subtest 'case 1' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
http2-graceful-shutdown-timeout: 0
hosts:
  default:
    paths:
      "/":
        - file.dir: @{[ DOC_ROOT ]}
EOT
    unless (fork) {
        Time::HiRes::sleep(1.5);
        kill 'TERM', $server->{pid};
        exit;
    }

    my $output = run_with_h2get_simple($server, <<"EOR");
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/",
    }
    h2g.send_headers(req, 1, END_HEADERS)
    sleep 2
    h2g.send_data(1, END_STREAM, '')

    loop do
        f = h2g.read(1000)
        if f == nil
            puts "timeout"
            exit 1
        end
        puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        if f.type == 'DATA' and f.is_end_stream
          puts 'received complete response'
          break
        end
    end
EOR
    like $output, qr{received complete response};
};

# 1. send headers
# 2. 1st goaway
# 3. 2nd goaway
# 4. send data (with END_STREAM flag)
subtest 'case 2' => sub {
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
http2-graceful-shutdown-timeout: 0
hosts:
  default:
    paths:
      "/":
        - file.dir: @{[ DOC_ROOT ]}
EOT
    unless (fork) {
        Time::HiRes::sleep(1.5);
        kill 'TERM', $server->{pid};
        exit;
    }

    my $output = run_with_h2get_simple($server, <<"EOR");
    req = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
        ":path" => "/",
    }
    h2g.send_headers(req, 1, END_HEADERS)
    sleep 3
    h2g.send_data(1, END_STREAM, '')

    loop do
        f = h2g.read(1000)
        if f == nil
            puts "timeout"
            exit 1
        end
        puts "#{f.type}, stream_id:#{f.stream_id}, len:#{f.len}, flags:#{f.flags}"
        if f.type == 'DATA' and f.is_end_stream
          puts 'received complete response'
          break
        end
    end
EOR
    like $output, qr{received complete response};
};

done_testing();
