use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

sub doit {
    my ($cmd, $format, @expected) = @_;

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

    $cmd->($server);

    my @log = do {
        open my $fh, "<", "$tempdir/access_log"
            or die "failed to open access_log:$!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };

    for (my $i = 0; $i != @expected; ++$i) {
        $expected[$i] = $expected[$i]->($server)
            if ref $expected[$i] eq 'CODE';
        like $log[$i], $expected[$i];
    }
}

subtest "custom-log" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent --referer http://example.com/ http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"',
        qr{^127\.0\.0\.1 - - \[[0-9]{2}/[A-Z][a-z]{2}/20[0-9]{2}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-][0-9]{4}\] "GET / HTTP/1\.1" 200 6 "http://example.com/" "curl/.*"$},
    );
};

subtest "more-fields" => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port}/ > /dev/null");
        },
        '\"%A:%p\"',
        sub { my $server = shift; qr{^\"127\.0\.0\.1:$server->{port}\"$} },
    );
};

subtest 'ltsv-related' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --silent http://127.0.0.1:$server->{port} > /dev/null");
            system("curl --silent http://127.0.0.1:$server->{port}/query?abc=d > /dev/null");
        },
        '%m::%U%q::%H::%V::%v',
        qr{^GET::/::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
        qr{^GET::/query\?abc=d::HTTP/1\.1::127\.0\.0\.1:[0-9]+::default$},
    );
};

subtest 'header-termination (issue 462)' => sub {
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{user-agent}i',
        qr{^foobar/1$},
    );
    doit(
        sub {
            my $server = shift;
            system("curl --user-agent foobar/1 --silent http://127.0.0.1:$server->{port} > /dev/null");
        },
        '%{content-type}o',
        qr{^text/plain$},
    );
};

done_testing;
