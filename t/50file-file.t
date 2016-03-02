use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'static' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /favicon.ico:
        file.file: @{[DOC_ROOT]}/halfdome.jpg
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $fetch = sub {
            my $path = shift;
            return `$cmd --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port$path 2>&1 > /dev/null`;
        };
        my $resp = $fetch->("/");
        like $resp, qr{^HTTP/[0-9\.]+ 404}is;
        $resp = $fetch->("/favicon.ico");
        like $resp, qr{^HTTP/[0-9\.]+ 200}is;
        like $resp, qr{^content-type:\s*image/jpeg\r$}im; # type is inferred from the extension of the real file
        like $resp, qr{^content-length:\s*@{[(stat "@{[DOC_ROOT]}/halfdome.jpg")[7]]}\r$}im;
    });
};

subtest 'dynamic' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn h2o
    my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      /robots.txt:
        file.file: @{[DOC_ROOT]}/hello.cgi
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/robots.txt?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

done_testing;
