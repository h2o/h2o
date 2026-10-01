use strict;
use warnings;
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $client_prog = bindir() . "/webtransport-client";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

sub spawn_wt_server {
    my $enabled = shift;
    spawn_h2o(<< "EOT");
webtransport: @{[ $enabled ? "ON" : "OFF" ]}
hosts:
  default:
    paths:
      /echo:
        webtransport.echo: ON
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
}

my @protocols = (
    { name => "h2", opts => "", port => sub { $_[0]->{tls_port} } },
    { name => "h3", opts => "-3", port => sub { $_[0]->{quic_port} } },
);

# runs the client, returning its output as an arrayref of lines, and the exit status
sub run_client {
    my ($server, $proto, $opts, $path, @actions) = @_;
    my $url = "https://127.0.0.1:@{[ $proto->{port}->($server) ]}$path";
    my $cmd = join " ", $client_prog, $proto->{opts}, $opts, "'$url'", map { "'$_'" } @actions;
    my $out = `$cmd 2> /dev/null`;
    my $status = $? >> 8;
    diag "$cmd:\n$out" if $ENV{TEST_DEBUG};
    return ([split /\n/, $out], $status);
}

# checks that the output contains all the expected lines, regardless of their order (the order of events on different streams is
# not deterministic)
sub has_lines {
    my ($out, $expected, $name) = @_;
    my %seen = map { $_ => 1 } @$out;
    my @missing = grep { !$seen{$_} } @$expected;
    ok !@missing, $name or diag "missing: @{[ join ', ', map { qq{'$_'} } @missing ]}\noutput:\n@{[ join qq{\n}, @$out ]}";
}

my $server = spawn_wt_server(1);

for my $proto (@protocols) {
    my $is_h3 = $proto->{name} eq 'h3';
    my $first_bidi = $is_h3 ? 4 : 0;           # stream 0 is the CONNECT stream in HTTP/3
    my $first_server_uni = $is_h3 ? 15 : 3;    # 3, 7, 11 are the control and QPACK streams in HTTP/3

    subtest $proto->{name} => sub {
        subtest "echo" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi:hello", "uni:world", "dgram:dg1");
            is $status, 0, "exit status";
            has_lines($out, [
                "response 200",
                "client-bidi[$first_bidi] fin \"hello\"",
                "server-uni[$first_server_uni] fin \"world\"",
                "datagram \"dg1\"",
                "done",
            ], "echoed");
            has_lines($out, ["settings wt-enabled=1"], "settings") if $is_h3;
        };

        subtest "large" => sub {
            # the size is limited for HTTP/2 by the default receive window of the stream (256KB) that the server advertises
            my $size = $is_h3 ? 1000000 : 200000;
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi:\@$size", "bidi:\@$size");
            is $status, 0, "exit status";
            has_lines($out, [
                "client-bidi[$first_bidi] fin <$size bytes, pattern ok>",
                "client-bidi[@{[ $first_bidi + 4 ]}] fin <$size bytes, pattern ok>",
            ], "echoed");
        };

        subtest "server-initiated streams" => sub {
            my ($out, $status) = run_client($server, $proto, "-e 4", "/echo?open-bidi=2&open-uni=2");
            is $status, 0, "exit status";
            has_lines($out, [
                "server-bidi[1] fin \"stream 1\\n\"",
                "server-bidi[5] fin \"stream 5\\n\"",
                "server-uni[$first_server_uni] fin \"stream $first_server_uni\\n\"",
                "server-uni[@{[ $first_server_uni + 4 ]}] fin \"stream @{[ $first_server_uni + 4 ]}\\n\"",
            ], "received");
        };

        subtest "reset and stop-sending are mirrored" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo", "bidi-reset:7", "bidi-stop:9");
            is $status, 0, "exit status";
            has_lines($out, [
                "client-bidi[$first_bidi] reset 7",
                "client-bidi[@{[ $first_bidi + 4 ]}] stop-sending 9",
                "client-bidi[@{[ $first_bidi + 4 ]}] reset 9",
            ], "mirrored");
        };

        subtest "server drains" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/echo?drain", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["drain", "client-bidi[$first_bidi] fin \"x\""], "drained");
        };

        subtest "server closes" => sub {
            my ($out, $status) = run_client($server, $proto, "-w", "/echo?close=42", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["close 42 \"bye\""], "closed");
        };

        subtest "client drains" => sub {
            my ($out, $status) = run_client($server, $proto, "-w", "/echo", "drain");
            is $status, 0, "exit status";
            has_lines($out, ["close 0 \"\""], "server closes in response");
        };

        subtest "client closes" => sub {
            my ($out, $status) = run_client($server, $proto, "-c 5", "/echo", "bidi:x");
            is $status, 0, "exit status";
            has_lines($out, ["client-bidi[$first_bidi] fin \"x\"", "done"], "closed");
        };

        subtest "not a WebTransport endpoint" => sub {
            my ($out, $status) = run_client($server, $proto, "", "/nope");
            is $status, 0, "exit status";
            has_lines($out, ["response 404"], "rejected");
        };
    };
}

subtest "disabled" => sub {
    my $server = spawn_wt_server(0);
    subtest "h2" => sub {
        my ($out) = run_client($server, $protocols[0], "-t 5000", "/echo", "bidi:x");
        ok !grep({ $_ eq "response 200" } @$out), "not established" or diag join "\n", @$out;
    };
    subtest "h3" => sub {
        my ($out) = run_client($server, $protocols[1], "-t 5000", "/echo", "bidi:x");
        has_lines($out, ["settings wt-enabled=0"], "not advertised");
        ok !grep({ $_ eq "response 200" } @$out), "not established";
    };
};

subtest "graceful shutdown" => sub {
    for my $proto (@protocols) {
        subtest $proto->{name} => sub {
            my $server = spawn_wt_server(1);
            my $url = "https://127.0.0.1:@{[ $proto->{port}->($server) ]}/echo";
            open my $fh, "-|", "$client_prog $proto->{opts} -w '$url' bidi:hi 2> /dev/null"
                or die "failed to spawn $client_prog: $!";
            sleep 3;
            kill 'TERM', $server->{pid};
            my @out = map { chomp; $_ } <$fh>;
            close $fh;
            is $? >> 8, 0, "exit status";
            has_lines(\@out, ["drain", "close 0 \"\""], "drained, then closed by the handler");
        };
    }
};

done_testing;
