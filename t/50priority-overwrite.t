# Regression test case for https://github.com/h2o/h2o/pull/2273
# Credit to OSS-Fuzz: This input pattern was found by OSS-Fuzz

use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(sub {
		my ($port, $tls_port) = @_;
		return << "EOT";
hosts:
  "*.localhost.examp1e.net:$tls_port":
    paths:
      /:
        file.dir: examples/doc_root
EOT
});

my ($output, $stderr) = run_with_h2get($server, <<"EOR");
begin
    to_process = []
    h2g = H2.new
    authority = ARGV[0]
    host = "https://#{authority}"
    h2g.connect(host)
    h2g.send_prefix()
    h2g.send_settings([[2,0], [4, 0xffff]])

    #
    # Kernel of the test input pattern
    #

    h2g.send_priority(7, 0, 1, 1)
    h2g.send_priority(9, 7, 1, 0)
    # Invalid DATA frame (as we have not sent HEADERS yet)
    # This will make stream 7 to be closed, send the associated scheduler openref
    # to recently_closed_stream
    h2g.send_data(7, 0x2, "00000")
    h2g.send_priority(7, 0, 1, 0)
    h2g.send_priority(9, 7, 1, 0) # This would have caused a crash without the fix

    #
    # End kernel
    #

    # Wait for the above frames to be sent out
    f = h2g.read(-1)
 
    h2g.close()
    h2g.destroy()
rescue => e
    p e
    exit 1
end
EOR

is $?, 0;

done_testing();
