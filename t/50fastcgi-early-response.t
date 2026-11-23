use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

# FastCGI application that sends the response as soon as it receives FCGI_PARAMS, without reading FCGI_STDIN
my $listener = IO::Socket::UNIX->new(
    Type   => SOCK_STREAM,
    Local  => "$tempdir/fcgi.sock",
    Listen => 5,
) or die "failed to listen:$!";
my $upstream = spawn_forked(sub {
    my @conns;
    while (my $conn = $listener->accept) {
        while (1) {
            read($conn, my $header, 8) == 8
                or die "failed to read record header";
            my ($type, $content_len, $padding_len) = (unpack "CCnnCx", $header)[1, 3, 4];
            read($conn, my $content, $content_len + $padding_len) == $content_len + $padding_len
                or die "failed to read record content";
            last if $type == 4 && $content_len == 0; # end of FCGI_PARAMS
        }
        my $record = sub {
            my ($type, $content) = @_;
            pack("CCnnCx", 1, $type, 1, length $content, 0) . $content;
        };
        print $conn $record->(6, "status: 200\r\ncontent-type: text/plain\r\n\r\nhello"), $record->(6, ""),
            $record->(3, pack("NCx3", 0, 0));
        $conn->flush;
        push @conns, $conn; # keep the connection open
    }
});

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        fastcgi.connect:
          port: $tempdir/fcgi.sock
          type: unix
fastcgi.timeout.keepalive: 5000
EOT

# the request body is large enough that h2o is still writing it when the application ends the response
my $body_file = create_data_file(4 * 1024 * 1024);
for my $i (1..2) {
    my $resp = `curl --silent --show-error --data-binary \@$body_file http://127.0.0.1:$server->{port}/`;
    is $resp, "hello", "response $i";
}

done_testing;
