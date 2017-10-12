use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'cgi file' => sub {
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

subtest 'cgi file with no extension' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn h2o
    my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: default
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      /robots.txt:
        file.file: @{[DOC_ROOT]}/noextcgi
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/robots.txt?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'directory containing cgi files' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn h2o
    my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: ["default", ".cgi"]
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/hello.cgi?name=Tobor`;
        is $resp, "Hello Tobor";
    });

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/noextcgi?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

subtest 'treat .html as cgi by resetting mimetypes' => sub {
    eval q{use CGI; 1}
        or plan skip_all => 'CGI.pm not found';

    # spawn h2o
    my $server = spawn_h2o(<< "EOT");
file.mime.settypes: {}
file.custom-handler:
  extension: ["default"]
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $resp = `$cmd --silent $proto://127.0.0.1:$port/cgi.html?name=Tobor`;
        is $resp, "Hello Tobor";
    });
};

done_testing;

