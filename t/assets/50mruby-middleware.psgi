use strict;
use warnings;
use Plack::App::File;
use Plack::TempBuffer;
use Plack::Builder;
use t::Util;

builder {
    # remove first path component if exists
    enable sub {
        my $app = shift;
        return sub {
            my $env = shift;
            my @comps = split('/', $env->{PATH_INFO});
            shift(@comps);
            shift(@comps) if scalar(@comps) > 1;
            unshift(@comps, '');
            $env->{PATH_INFO} = join('/', @comps);
            my $res = $app->($env);
            return $res;
        };
    };
    mount "/" => Plack::App::File->new(root => DOC_ROOT)->to_app;
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
};
