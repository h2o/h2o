use strict;
use warnings;
use Plack::App::File;
use Plack::Builder;
use Plack::Request;
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
                my @headers;
                for (my $i = 0; $i != @{$res->[1]}; $i += 2) {
                    push @headers, $res->[1][$i], $res->[1][$i + 1]
                        if lc $res->[1][$i] ne 'content-length';
                }
                $res->[1] = \@headers;
                return $res;
            };
        };
    }
    mount "/" => Plack::App::File->new(root => DOC_ROOT)->to_app;
    mount "/echo" => sub {
        my $env = shift;
        my $content = '';
        if ($env->{'psgi.input'}) {
            $env->{'psgi.input'}->read($content, 104857600);
        }
        return [
            200,
            [
                'content-type' => 'text/plain',
                'content-length' => length $content,
            ],
            [ $content ],
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
                join "\n", map { my $n = lc substr $_, 5; $n =~ tr/_/-/; "$n: $env->{$_}" } sort grep { /^HTTP_/ } keys %$env,
            ]
        ];
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
};
