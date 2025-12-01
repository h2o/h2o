# This script runs the simulator with the given arguments specifying the network condition, with rapid start
# on and off, and generates a gnuplot script that compares the results.
use strict;
use warnings;
use Getopt::Long;
use JSON;

my $simulator = ($ENV{BINARY_DIR} || ".") . "/simulator";

my $NETWORKS = {
    DSL => {
        rtt   => .03,
        queue => .05,
        bw    => 30e6,
    },
    Home_WiFi => {
        rtt   => .025,
        queue => .015,
        bw    => 100e6, 
    },
    Public => {
        rtt   => .04,
        queue => .2, # bufferbloat
        bw    => 20e6, 
    },
    Corporate_WiFi => {
        rtt   => .01,
        queue => .02,
        bw    => 500e6, 
    },
    LTE => {
        rtt   => .06,
        queue => .12,
        bw    => 30e6, 
    },
    '5G' => {
        rtt   => .04,
        queue => .08,
        bw    => 100e6, 
    },
    LEO => {
        rtt   => .04,
        queue => .08,
        bw    => 50e6, 
    },
    GEO => {
        rtt   => .6,
        queue => .6,
        bw    => 50e6,
    },
    'DoCoMo@Office' => {
        rtt   => .028,
        queue => .245 - .028,
        bw    => 140e6,
    },
    'au@Office' => {
        rtt   => .02,
        queue => .253 - .02,
        bw    => 440e6,
    },
    'WiFi@Office' => {
        rtt   => .004,
        queue => .015 - .004,
        bw    => 710e6,
    },
    'DoCoMo@mall' => {
        rtt   => .041,
        queue => .341 - .041,
        bw    => 38e6,
    },
    congested => {
        rtt   => 0.2,
        queue => 0.4,
        bw    => 1e6,
    },
    bdp20 => {
        rtt   => 0.1,
        queue => 0.1,
        bw    => 1e6,
    },
    bdp40 => {
        rtt   => 0.1,
        queue => 0.1,
        bw    => 2e6,
    },
};

my $cc = 'pico';
my $length = 1;
my $network = $NETWORKS->{DSL};
my $show_queue;

# get options applied to all simulations
GetOptions(
    "cc=s" => \$cc,
    "length=f" => \$length,
    "network=s" => sub {
        my ($optname, $optval) = @_;
        $network = $NETWORKS->{$optval}
            or die "unknown network: $optval";
    },
    "queue" => \$show_queue,
) or die "bad options";

# get options for each flow
my @flows;
while (@ARGV) {
    my $label = shift;
    my @flow_opts;
    while (@ARGV && $ARGV[0] ne '--') {
        push @flow_opts, shift(@ARGV);
    }
    push @flows, [$label, \@flow_opts];
    shift @ARGV; # remove the -- separator
}

die "--queue cannot be used when multiple flows are given\n"
    if $show_queue && @flows > 1;

# run simulations
for my $flow (@flows) {
    open(
        my $fh, "-|", $simulator, @{$flow->[1]},
        '-d', $network->{rtt},
        '-q', $network->{queue},
        '-b', $network->{bw} / 8,
        '-l', $length,
        '-n', $cc,
    ) or die "failed to run simulator: $!";
    my ($bytes_avail, $queue_size) = simout_to_xy($fh);
    close $fh
        or die "simulator exited with a non-zero exit code: $?";
    print << "GP";
\$F_$flow->[0] << EOD
${bytes_avail}EOD
\$Q_$flow->[0] << EOD
${queue_size}EOD
GP
}

print << "GP";
set xrange [0:$length]
set key left top
set y2tics
GP

print "plot ", join(", ", map {
    qq!\$F_$_->[0] using 1:2 axis x1y1 with lines title "$_->[0] - deliver"!
} @flows), "\n";
if ($show_queue) {
    print "replot ", join(", ", map {
        qq!\$Q_$_->[0] using 1:2 axis x1y2 with lines title "$_->[0] - queue"!
    } @flows), "\n";
}

# given the output of the simulator, convert to x,y pairs for gnuplot
sub simout_to_xy {
    my $fh = shift;
    my $bytes_avail = "";
    my $queue_size = "";
    while (my $line = <$fh>) {
        my $json = decode_json($line);
        if ($json->{"bytes-available"}) {
            $bytes_avail .= "@{[$json->{at} - 1000]} $json->{\"bytes-available\"}\n";
        } elsif ($json->{bottleneck} && $json->{bottleneck} eq 'dequeue') {
            $queue_size .= "@{[$json->{at} - 1000]} $json->{\"queue-size\"}\n";
        }
    }
    return ($bytes_avail, $queue_size);
}
