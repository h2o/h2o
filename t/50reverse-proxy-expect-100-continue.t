use strict;
use warnings;
use Test::More;
use Time::HiRes;
use t::Util;
use IO::Select;
use IO::Socket::INET;

plan skip_all => "nc not found"
    unless prog_exists("nc");

my $h1_upstream_port = empty_port();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /h1:
        proxy.expect: ON
        proxy.reverse.url: http://127.0.0.1:$h1_upstream_port
EOT

subtest 'h1 upstream' => sub {
    my $upstream = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $h1_upstream_port,
        Proto => 'tcp',
        Listen => 1,
    ) or die $!;

    subtest 'basic' => sub {
        my $c = spawn_forked(sub {
            print `curl --http2 -s -X POST --data-binary xxxxx http://127.0.0.1:$server->{port}/h1`;
        });
        
        my $client = $upstream->accept;
        my $chunk;
        
        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        like $header, qr/expect: *100-continue/i;
        
        note 'test that h2o never send req body before this server respond with 100 continue';
        ok(! IO::Select->new([ $client ])->can_read(1));
        
        note 'send 100 continue';
        $client->syswrite("HTTP/1.1 100 Continue\r\n\r\n");
        
        note 'then h2o should have sent the body';
        ok(IO::Select->new([ $client ])->can_read(1));
        
        note 'read body';
        my $body;
        is $client->sysread($body, 5), 5;
        is $body, 'xxxxx';
        
        my $content = "Good waiting! You're awesome!";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);
        
        my ($cout) = $c->{wait}->();
        
        is $cout, $content;
    };

    subtest 'no 100 response' => sub {
        my $c = spawn_forked(sub {
            print `curl --http2 -s -X POST --data-binary xxxxx http://127.0.0.1:$server->{port}/h1`;
        });
        
        my $client = $upstream->accept;
        my $chunk;
        
        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        like $header, qr/expect: *100-continue/i;

        note 'test that h2o never send req body before this server respond with 100 continue';
        ok(! IO::Select->new([ $client ])->can_read(1));

        my $content = "What do you expect from me? Just zip it and dig in!";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);
        
        note 'then h2o should have sent the body';
        ok(IO::Select->new([ $client ])->can_read(1));
        
        note 'read body';
        my $body;
        is $client->sysread($body, 5), 5;
        is $body, 'xxxxx';
        
        my ($cout) = $c->{wait}->();
        
        is $cout, $content;
    };

    subtest 'no body' => sub {
        my $c = spawn_forked(sub {
            print `curl -X GET -s http://127.0.0.1:$server->{port}/h1`;
        });

        my $client = $upstream->accept;
        my $chunk;

        note 'read header';
        my $header = '';
        while ($client->sysread($chunk, 1) > 0) {
            $header .= $chunk;
            last if $header =~ /\r\n\r\n$/;
        }
        unlike $header, qr/expect: *100-continue/i;

        my $content = "Hello, you sent no body";
        $client->syswrite(join("\r\n", (
            "HTTP/1.1 200 OK",
            "Content-Length: @{[length($content)]}",
            "", ""
        )) . $content);

        my ($cout) = $c->{wait}->();

        is $cout, $content;
    };

};

subtest 'h2 upstream' => sub {
    plan skip_all => 'TODO';
};

subtest 'h3 upstream' => sub {
    plan skip_all => 'TODO';
};

done_testing;
