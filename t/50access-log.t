use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

sub doit {
    my ($testname, $getcurlopts, $format, $expected) = @_;

    subtest $testname => sub {
        unlink "$tempdir/access_log";

        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
    access-log:
      format: "$format"
      path: $tempdir/access_log
EOT

        system("curl --silent @{[$getcurlopts->($server)]} > /dev/null");

        my $log = do {
            open my $fh, "<", "$tempdir/access_log"
                or die "failed to open access_log:$!";
            join "", <$fh>;
        };

        like $log, $expected;
    };
}

doit(
    "custom-log",
    sub {
        my $server = shift;
        "--referer http://example.com/ http://127.0.0.1:$server->{port}/";
    },
    '%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"',
    qr{^127\.0\.0\.1 - - \[[0-9]{2}/[A-Z][a-z]{2}/20[0-9]{2}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-][0-9]{4}\] "GET / HTTP/1\.1" 200 6 "http://example.com/" "curl/.*"\n$},
);

done_testing;
