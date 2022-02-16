# Tests absolute priority headers added by mruby backend
#
# Overview of the test
# 1. client sends request URI with query string u=X
# 2. mruby parses the query string and adds a priority
#    header to the response
# 3. H2O parses the priority header and modifies stream
#    priority
# 4. test case verifies the order of the returned stream
#    to make sure the prioritization works
use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

sub test_priority_header {
    my ($input_streams, $expected_order) = @_;
    my $server = spawn_h2o(sub {
            my ($port, $tls_port) = @_;
            return << "EOT";
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/wildcard.key
    certificate-file: examples/h2o/wildcard.crt
hosts:
  "*.localhost.examp1e.net:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
        mruby.handler: |
          lambda do |env|
            path = env["PATH_INFO"]
            qs = env["QUERY_STRING"]
            if qs.match(/u=[0-7]/)
              # Add the urgency parameter based on query string sent by the client
              prio = { 'Priority' => qs }
            else
              prio = {}
            end
            fn = "t/assets/doc_root/" + path
            # Read the file to a buffer first to prevent blocking
            # when serving the request, which could lead to spurious
            # priority inversion.
            # Assumed file (t/assets/doc_root/halfdome.jpg) is less
            # than 500KB, so 1MB buffer should be enough to read the
            # entire file.
            [200, prio, [File.open(fn).read(1048576)]]
          end
EOT
        });

    my ($output, $stderr) = run_with_h2get($server, <<"EOR");
    # Client-side code, based on h2get/firefox.rb
    h2g = H2.new
    authority = ARGV[0]
    host = "https://#{authority}"
    h2g.connect(host)
    h2g.send_prefix()
    # Enlarge initial window size to avoid unnecessary blocking within a stream,
    # which could lead to an unexpected priority inversion
    h2g.send_settings([[2,0], # ENABLE_PUSH = 0
                       [4,1048576] # INITIAL_WINDOW_SIZE = 1MB
                      ])
    open_streams = {}
    # Ack settings
    while true do
        f = h2g.read(-1)
        if f.type == "SETTINGS" and (f.flags & 1 == 1) then
            next
        elsif f.type == "SETTINGS" then
            h2g.send_settings_ack()
            break
        end
    end

    input_streams = $input_streams
    stream_order = $expected_order
    n_headers_got = 0 # number of streams that we got HEADERS from the server
    n_completed_streams = 0
    errs = 0
    next_stream = 1
    dep_stream = 0
    req_base = {
        ":method" => "GET",
        ":authority" => host,
        ":scheme" => "https",
    }
    input_streams.each do |s|
        path = "/halfdome.jpg"
        weight = s[0]
        u = s[1]
        if u >=0 then
            # Add a query string to tell the server what urgency we want
            path += "?u=#{u}"
        end
        req = req_base.merge(":path" => path)
        # Partially mimics Chromium's behavior in generating requests and priorities
        # - Requests form a linear list (each stream has no more than one child)
        # - Requests are ordered by weight in descending order
        priority = H2Priority.new(dep_stream, 1, weight - 1)
        h2g.send_headers(req, next_stream, PRIORITY | END_STREAM | END_HEADERS, priority)
        open_streams[next_stream] = 1

        dep_stream = next_stream
        next_stream += 2
    end

    # Main loop
    while open_streams.length > 0
        f = h2g.read(-1)
        if f.type == "PING" then
            f.ack()
        elsif f.type == "DATA" then
            if n_headers_got == input_streams.length then
                # Server is now sending all streams -- verify if the streams are in the expected order
                expected_id = stream_order[n_completed_streams]
                if f.stream_id != expected_id then
                    puts "Expected stream #{expected_id} but got stream #{f.stream_id}" if errs == 0
                    errs += 1
                end
            end
            if f.len > 0 then
                h2g.send_window_update(0, f.len)
                h2g.send_window_update(f.stream_id, f.len)
            end
        elsif f.type == "HEADERS" && f.flags & END_HEADERS then
            n_headers_got += 1
        end

        if (f.type == "DATA" or f.type == "HEADERS") and f.is_end_stream
            open_streams.delete(f.stream_id)
            n_completed_streams += 1
        end
    end
    h2g.close()
    h2g.destroy()

    if errs > 0 then
        puts "Encontered #{errs} errors"
        exit 1
    end
    puts "No errors"
EOR
    print $stderr;
    is $?, 0;
}

# test_priority_header(input_streams, expected_order)
#   input_streams: array of [initial weight, urgency]
#   expected_order: array of stream ID
test_priority_header("[[128, 2], [128, 1], [128, 0]]", "[5, 3, 1]");
test_priority_header("[[128, 0], [128, 1], [128, 2]]", "[1, 3, 5]");
test_priority_header("[[128, 0], [128, 0], [128, 0]]", "[1, 3, 5]");
test_priority_header("[[128, 0], [128, 7], [128, 0]]", "[1, 5, 3]");
# Negative urgency == no priority headers added
test_priority_header("[[128, -1], [128, -1], [128, 0]]", "[5, 1, 3]");
test_priority_header("[[128, -1], [128, 0], [128, -1]]", "[3, 1, 5]");
test_priority_header("[[128, -1], [128, -1], [128, -1]]", "[1, 3, 5]");
# Demotion
test_priority_header("[[128, 7], [128, -1], [128, -1]]", "[3, 5, 1]");
test_priority_header("[[128, -1], [128, 7], [128, -1]]", "[1, 5, 3]");
test_priority_header("[[128, -1], [128, -1], [128, 7]]", "[1, 3, 5]");
# No reprioritization
test_priority_header("[[128, -1], [128, -1], [128, -1]]", "[1, 3, 5]");
# Properly ignore non-chromium-style dependency tree?
test_priority_header("[[128, 2], [130, 1], [128, 0]]", "[1, 3, 5]");

done_testing();
