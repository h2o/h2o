use strict;
use warnings;
use Plack::App::File;
use Plack::Builder;

builder {
    mount "/" => Plack::App::File->new(root => "t/50end-to-end/reverse-proxy/docroot")->to_app;
    mount "/echo" => sub {
        my $env = shift;
        my $content = '';
        if ($env->{'psgi.input'}) {
            $env->{'psgi.input'}->read($content, 1048576);
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
};
