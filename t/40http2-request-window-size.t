use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

sub doit {
    my ($proto, $port) = @_;
    my $output = `nghttp -n -v -d @{[DOC_ROOT]}/halfdome.jpg $proto://127.0.0.1:$port/ 2>&1`;
    like $output, qr{recv WINDOW_UPDATE frame [^>]*stream_id=0>\s*\(window_size_increment=167[0-9]{5}\)}, "connection-level set to 16M";
    like $output, qr{recv WINDOW_UPDATE frame [^>]*stream_id=[1-9][0-9]*>\s*\(window_size_increment=167[0-9]{5}\)}, "stream set to 16M";
}

doit('http', $server->{port});
doit('https', $server->{tls_port});

done_testing();
