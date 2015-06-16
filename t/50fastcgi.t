use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'cannot run perl -MPlack::Handler::FCGI'
    if system("perl -MPlack::Handler::FCGI /dev/null > /dev/null 2>&1") != 0;

my $tempdir = tempdir(CLEANUP => 1);
my $fcgi_port = empty_port();

# gather information of test data
my %files = map { do {
    my $fn = DOC_ROOT . "/$_";
    +($_ => { size => (stat $fn)[7], md5 => md5_file($fn) });
} } qw(index.txt halfdome.jpg);

sub doit {
    my ($tcp, $keepalive) = @_;
    subtest "tcp:$tcp,keepalive:$keepalive" => sub {
        # spawn upstream
        unlink "$tempdir/fcgi.sock";
        my $upstream = spawn_server(
            argv => [
                qw(plackup -s FCGI --access-log /dev/null --listen),
                ($tcp ? ":$fcgi_port" : "$tempdir/fcgi.sock"),
                ASSETS_DIR . "/upstream.psgi",
            ],
            is_ready => sub {
                $tcp ? check_port($fcgi_port) : -e "$tempdir/fcgi.sock";
            },
        );
        # spawn h2o
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
         fastcgi.connect:
           @{[$tcp ? "host: 127.0.0.1" : ""]}
           port: @{[$tcp ? $fcgi_port : "$tempdir/fcgi.sock"]}
           type: @{[$tcp ? "tcp" : "unix"]}
fastcgi.timeout.keepalive: @{[$keepalive ? 5000 : 0]}
EOT
        # the tests
        subtest 'files' => sub {
            my $doit = sub {
                my ($proto, $port) = @_;
                for my $file (sort keys %files) {
                    my $content = `curl --silent --show-error --insecure $proto://127.0.0.1:$port/$file`;
                    is length($content), $files{$file}->{size}, "$proto://127.0.0.1/$file (size)";
                    is md5_hex($content), $files{$file}->{md5}, "$proto://127.0.0.1/$file (md5)";
                }
            };
            $doit->('http', $server->{port});
            $doit->('https', $server->{tls_port});
        };
        subtest 'echo' => sub {
            # send header that exceeds the max. length fcgi record (the size of the response also exceeds the record size, and uses chunked encoding)
            my $doit = sub {
                my ($proto, $port) = @_;
                my $content = `curl --silent --show-error --insecure -H foo:@{["0123456789"x7000]} $proto://127.0.0.1:$port/echo-headers`;
                like $content, qr/^foo: (0123456789){7000,7000}$/mi;
            };
            $doit->('http', $server->{port});
        };
        subtest 'cookie-merge' => sub {
            plan skip_all => "curl does not support HTTP/2"
                unless curl_supports_http2();
            plan skip_all => "cowardly skipping to avoid https://github.com/plack/Plack/pull/511; unless PLACK_ENV=deployment is set"
                unless $ENV{PLACK_ENV} && $ENV{PLACK_ENV} eq 'deployment';
            my $content = `curl --http2 --silent --show-error --insecure -H "cookie:a=b;c=d" https://127.0.0.1:$server->{tls_port}/echo-headers`;
            like $content, qr/^cookie: a=b;\s*c=d$/mi;
        };
        delete $server->{guard};
    };
}

doit(0, 0);
doit(1, 0);
doit(1, 1);
doit(1, 1);

done_testing();
