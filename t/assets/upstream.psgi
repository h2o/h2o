use strict;
use warnings;
use Digest::SHA qw(sha1_base64);
use Plack::App::File;
use Plack::Builder;
use Plack::Request;
use Plack::TempBuffer;
use Time::HiRes qw(sleep);
use t::Util;

my $force_chunked = $ENV{FORCE_CHUNKED} || 0;

builder {
    enable sub {
        my $app = shift;
        return sub {
            my $env = shift;
            my $query = Plack::Request->new($env)->query_parameters;
            my $res = $app->($env);
            Plack::Util::response_cb($res, sub {
                my $res = shift;
                if ($query->{"resp:status"}) {
                    $res->[0] = $query->get("resp:status");
                    $query->remove("resp:status");
                }
                push @{$res->[1]}, map {
                    my $n = $_;
                    +(substr($n, length "resp:") => $query->get($n))
                } grep {
                    $_ =~ /^resp:/
                } $query->keys;
                $res;
            });
        };
    };
    if ($force_chunked) {
        enable sub {
            my $app = shift;
            return sub {
                my $env = shift;
                my $res = $app->($env);
                Plack::Util::response_cb($res, sub {
                    my $res = shift;
                    my @headers;
                    for (my $i = 0; $i != @{$res->[1]}; $i += 2) {
                        push @headers, $res->[1][$i], $res->[1][$i + 1]
                            if lc $res->[1][$i] ne 'content-length';
                    }
                    $res->[1] = \@headers;
                    return $res;
                });
            };
        };
    }
    mount "/" => Plack::App::File->new(root => DOC_ROOT)->to_app;
    mount "/echo-query" => sub {
        my $env = shift;
        return [
            200,
            [
                'content-type' => 'text/plain',
            ],
            [$env->{QUERY_STRING}],
        ];
    };
    mount "/echo" => sub {
        my $env = shift;
        my $content = Plack::TempBuffer->new;
        if ($env->{'psgi.input'}) {
            my $buf;
            while ($env->{'psgi.input'}->read($buf, 65536)) {
                $content->print($buf);
            }
        }
        return [
            200,
            [
                'content-type' => 'text/plain',
                'content-length' => $content->size(),
            ],
            $content->rewind(),
        ];
    };
    mount "/echo-headers" => sub {
        my $env = shift;
        return [
            200,
            [
                'content-type' => 'text/plain',
            ],
            [
                join "\n", map { my $n = lc $_; $n=~ s/^http_//; $n =~ tr/_/-/; "$n: $env->{$_}" } sort grep { /^(HTTP_|HTTPS$)/ } keys %$env,
            ]
        ];
    };
    mount "/custom-perl" => sub {
        my $env = shift;
        my $c = "";
        if ($env->{'psgi.input'}) {
            my $buf;
            while ($env->{'psgi.input'}->read($buf, 65536)) {
                $c = $c . $buf;
            }
        }
        return eval($c);
    };
    mount "/echo-server-header" => sub {
        my $env = shift;
        my @resph = [ 'content-type' => 'text/plain' ];
        if ($env->{HTTP_SERVER}) {
            @resph = [ 'content-type' => 'text/plain', 'server' => $env->{HTTP_SERVER} ];
        }
        return [
            200, @resph, [ "Ok" ]
        ];
    };
    mount "/echo-request-uri" => sub {
        my $env = shift;
        return [
            200,
            [
            ],
            [$env->{"REQUEST_URI"} || ''],
        ];
    };
    mount "/echo-server-port" => sub {
        my $env = shift;
        return [
            200,
            [
                'x-server' => $env->{"SERVER_PORT"},
                'req-connection' => $env->{"HTTP_CONNECTION"} || '',
            ],
            [$env->{"SERVER_PORT"}],
        ];
    };
    mount "/echo-remote-port" => sub {
        my $env = shift;
        return [
            200,
            [
            ],
            [$env->{"REMOTE_PORT"} || ''],
        ];
    };
    mount "/sni-name" => sub {
        my $env = shift;
        [200, [], [$env->{"psgix.io"}->get_servername]];
    };
    mount "/suspend-body" => sub {
        my $env = shift;
        return sub {
            my $responder = shift;
            my $writer = $responder->([ 200, [ 'content-type' => 'text/plain' ] ]);
            sleep 1;
            $writer->write('x');
            $writer->close;
        };
    };
    mount "/streaming-body" => sub {
        my $env = shift;
        return sub {
            my $responder = shift;
            my $writer = $responder->([ 200, [ 'content-type' => 'text/plain' ] ]);
            for my $i (1..30) {
                sleep 0.1;
                $writer->write($i);
            }
            $writer->close;
        };
    };
    mount "/sleep-and-respond" => sub {
        my $env = shift;
        my $query = Plack::Request->new($env)->parameters;
        sleep($query->{sleep} || 0);
        return [
            200,
            [
                'content-type' => 'text/plain; charset=utf-8',
            ],
            [
                'hello world',
            ],
        ];
    };
    mount "/fixed-date-header" => sub {
        my $env = shift;
        return [
            200,
            [
                'content-type' => 'text/plain',
                'date' => 'Thu, 01 Jan 1970 00:00:00 GMT',
            ],
            []
        ];
    };
    mount "/infinite-stream" => sub {
        my $env = shift;
        return sub {
            my $responder = shift;
            my $writer = $responder->([ 200, [ 'content-type' => 'text/plain' ] ]);
            while ($writer->write("lorem ipsum dolor sit amet")) {
                sleep 0.1;
            }
            $writer->close;
        };
    };
    mount "/infinite-redirect" => sub {
        my $env = shift;
        return [
            302,
            [
                location => '/infinite-redirect',
            ],
            [],
        ];
    };
    mount "/websocket" => sub {
        my $env = shift;
        my $key = $env->{HTTP_SEC_WEBSOCKET_KEY}
            or return [400, [], ["no Sec-WebSocket-Key"]];
        $key .= "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        my $accept_key = sha1_base64($key);
        my $fh = $env->{"psgix.io"};
        print $fh join(
            "\r\n",
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Sec-Websocket-Accept: $accept_key",
            "",
            "",
        );
        while (1) {
            my $rfds = '';
            vec($rfds, fileno($fh), 1) = 1;
            next if select($rfds, undef, undef, undef) <= 0;
            $fh->sysread(my $data, 65536) <= 0
                and last;
            while (length($data) != 0) {
                my $wfds = '';
                vec($wfds, fileno($fh), 1) = 1;
                next if select(undef, $wfds, undef, undef) <= 0;
                my $wlen = $fh->syswrite($data);
                last if $wlen <= 0;
                $data = substr $data, $wlen;
            }
        }
        close $fh;
        exit 0;
    };
    mount "/1xx-push" => sub {
        my $env = shift;
        my $fh = $env->{"psgix.io"};
        print $fh join(
            "\r\n",
            "HTTP/1.1 100 Continue",
            "link: </index.js>; rel=preload",
            "",
            "HTTP/1.1 100 Continue",
            "link: </index.js>; rel=preload",
            "",
            "",
        );
        sleep 1.1;
        [200, ["content-type" => "text/plain; charset=utf-8", "content-length" => 11], ["hello world"]];
    };
    mount "/push-attr" => sub {
        my $env = shift;
        my $query = Plack::Request->new($env)->query_parameters;
        [200, ["content-type" => "text/plain; charset=utf-8", "content-length" => 11, "link" => "$query->{'pushes'}"], ["hello world"]];
    };
    mount "/no-content" => sub {
        my $env = shift;
        return [
            204,
            [
                'content-type' => 'text/plain',
            ],
            [],
        ];
    };
    mount "/content" => sub {
        my $env = shift;
        my $query = Plack::Request->new($env)->query_parameters;
        return [
            200,
            [
                ($query->{cl} ? ( 'content-length' => $query->{cl}) : ())
            ],
            [ 'a' x ($query->{size} || 0) ],
        ];
    };
    mount "/1xx" => sub {
        my $env = shift;
        my $query = Plack::Request->new($env)->query_parameters;
        my $status = $query->get('status') || 100;
        my $fh = $env->{"psgix.io"};
        print $fh join(
            "\r\n",
            "HTTP/1.1 $status OK",
            ($query->get('link') ? (
                "link: </index.js>; rel=preload",
            ) : ()),
            "",
            "HTTP/1.1 $status OK",
            ($query->get('link') ? (
                "link: </style.css>; rel=preload",
            ) : ()),
            "",
            "HTTP/1.1 200 OK",
            "connection: close",
            "content-type: text/plain",
            "content-length: 11",
            "",
            "hello world",
        );
        return sub {}; # do nothing
    };
};
