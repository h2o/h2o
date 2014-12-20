use strict;
use warnings;
use Plack::App::File;
use Plack::Builder;

my $force_chunked = $ENV{FORCE_CHUNKED} || 0;

builder {
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
            }
        };
    }
    mount "/" => Plack::App::File->new(root => "t/doc_root")->to_app;
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
                map { my $n = lc substr $_, 5; $n =~ s/_/-/; "x-req-$n" => $env->{$_} } sort grep { /^HTTP_/ } keys %$env,
            ],
            [ $content ],
        ];
    };
    mount "/redirect" => sub {
        my $env = shift;
        return [
            302,
            [
                location => substr($env->{PATH_INFO}, 1),
            ],
            [],
        ];
    };
};
