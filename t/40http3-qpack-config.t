use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

# Best-effort coverage that the QPACK encoder/decoder config knobs are actually applied at runtime, and that the corresponding
# access-log specifiers (`http3.qpack.encoder-stats` / `http3.qpack.decoder-stats`) report sane values. We assert that the relevant
# instruction counters move (or stay at zero), not exact counts.

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);

# Parses a "key=value,key=value,..." qpack stats string into a hashref.
sub parse_stats {
    my ($s) = @_;
    my %h;
    for my $kv (split /,/, $s) {
        my ($k, $v) = split /=/, $kv, 2;
        $h{$k} = $v if defined $v;
    }
    return \%h;
}

# Spawns h2o with the given `quic:` qpack snippet (may be empty) plus any extra path config, runs $client_cb->($quic_port), and
# returns the peak { enc => {...}, dec => {...} } instruction counters across all logged requests (the counters are cumulative per
# connection, so the peak is the final state).
sub run_and_collect {
    my ($qpack_conf, $extra_paths, $client_cb, $global_conf) = @_;
    my $quic_port = empty_port({ host => "127.0.0.1", proto => "udp" });
    my $access_log = "$tempdir/access.log";
    unlink $access_log;
    $extra_paths //= "";
    $global_conf //= "";
    my $server = spawn_h2o(<< "EOT");
$global_conf
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
$qpack_conf  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
access-log:
  path: $access_log
  format: "enc=%{http3.qpack.encoder-stats}x dec=%{http3.qpack.decoder-stats}x"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
$extra_paths
EOT
    $client_cb->($quic_port);
    undef $server; # graceful shutdown flushes the access log

    my (%enc, %dec);
    open my $fh, "<", $access_log
        or die "failed to open $access_log:$!";
    while (my $line = <$fh>) {
        next
            unless $line =~ /enc=(\S+) dec=(\S+)/;
        my ($e, $d) = (parse_stats($1), parse_stats($2));
        for my $k (keys %$e) { $enc{$k} = $e->{$k} if !defined $enc{$k} || $e->{$k} > $enc{$k} }
        for my $k (keys %$d) { $dec{$k} = $d->{$k} if !defined $dec{$k} || $d->{$k} > $dec{$k} }
    }
    close $fh;
    return { enc => \%enc, dec => \%dec };
}

sub inserts {
    my ($s) = @_;
    return ($s->{"num-instructions.insert-with-name-reference"} // 0) +
        ($s->{"num-instructions.insert-without-name-reference"} // 0);
}

my $fetch_file = sub {
    my $port = shift;
    system("$client_prog -k -3 100 -t 5 --http3-qpack-decoder-table-capacity 4096 " .
           "https://127.0.0.1:$port/halfdome.jpg > /dev/null 2>&1");
};

my $fetch_file_without_response_table = sub {
    my $port = shift;
    system("$client_prog -k -3 100 -t 5 https://127.0.0.1:$port/halfdome.jpg > /dev/null 2>&1");
};

sub fetch_with_client_header {
    my ($client_args) = @_;
    return sub {
        my $port = shift;
        system("$client_prog -k -3 100 -t 5 $client_args -H x-codec-test:abcdefghijklmnopqrstuvwxyz " .
               "https://127.0.0.1:$port/ > /dev/null 2>&1");
    };
}

subtest "server encoder uses the dynamic table by default" => sub {
    my $stats = run_and_collect("", "", $fetch_file);
    cmp_ok inserts($stats->{enc}), ">", 0, "encoder-stats reports inserts";
};

subtest "client decoder table disabled => server encoder sees no inserts" => sub {
    my $stats = run_and_collect("", "", $fetch_file_without_response_table);
    is inserts($stats->{enc}), 0, "encoder-stats reports no inserts when the client does not advertise a decoder table";
};

subtest "server encoder table disabled => no inserts" => sub {
    my $stats = run_and_collect("  quic:\n    qpack-encoder-table-capacity: 0\n", "", $fetch_file);
    is inserts($stats->{enc}), 0, "encoder-stats reports no inserts when the encoder table is disabled";
};

subtest "server decoder reports inserts received from the client" => sub {
    plan skip_all => "h2o-httpclient does not emit request QPACK encoder-stream inserts";

    my $stats = run_and_collect("", "", fetch_with_client_header(""));
    cmp_ok inserts($stats->{dec}), ">", 0, "decoder-stats reports inserts received from the client";
};

subtest "client encoder table disabled => decoder sees no inserts" => sub {
    plan skip_all => "h2o-httpclient does not emit request QPACK encoder-stream inserts";

    my $stats = run_and_collect("", "", fetch_with_client_header("--http3-qpack-encoder-table-capacity 0"));
    is inserts($stats->{dec}), 0, "decoder-stats reports no inserts when the client encoder table is disabled";
};

subtest "server encoder refinement emits Duplicate (refine on vs off)" => sub {
    plan skip_all => "mruby is off"
        unless server_features()->{mruby};

    # Keep automatic response headers out of the tiny table: Server is disabled, and Date is provided with a short value that is
    # not worth inserting. The 96-byte table holds exactly two custom 43-byte entries. The first response fills it with x-a/x-b and
    # records x-c as shadow evidence; repeated x-a makes it a keeper, then repeated x-c beats x-b but not x-a, forcing Duplicate.
    my $mruby = << 'EOT';
      "/swap":
        mruby.handler: |
          cnt = 0
          Proc.new do |env|
            cnt += 1
            h = {"date" => "x"}
            if cnt == 1
              h["x-a"] = "aaaaaaaa"
              h["x-b"] = "bbbbbbbb"
              h["x-c"] = "cccccccc"
            elsif cnt <= 21
              h["x-a"] = "aaaaaaaa"
            else
              h["x-c"] = "cccccccc"
            end
            [200, h, ["hello\n"]]
          end
EOT
    my $swap_client = sub {
        my $port = shift;
        system("$client_prog -k -3 100 -t 31 --http3-qpack-decoder-table-capacity 4096 " .
               "https://127.0.0.1:$port/swap > /dev/null 2>&1");
    };

    my $global_conf = "send-server-name: OFF\n";
    my $on = run_and_collect("  quic:\n    qpack-encoder-table-capacity: 96\n", $mruby, $swap_client, $global_conf);
    cmp_ok $on->{enc}{"num-instructions.duplicate"} // 0, ">", 0, "refine on => Duplicate emitted";

    my $off = run_and_collect("  quic:\n    qpack-encoder-table-capacity: 96\n    qpack-encoder-refine: OFF\n", $mruby,
                              $swap_client, $global_conf);
    is $off->{enc}{"num-instructions.duplicate"} // 0, 0, "refine off => no Duplicate";
};

done_testing;
