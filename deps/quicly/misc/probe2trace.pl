#! /bin/sh
exec perl -x $0 "$@"
#! perl

use strict;
use warnings;

# read file and build list of probes being [[probe_name0, [[arg0_name, arg0_type], [arg1_name, arg1_type], ...], [probe_name2, ...
my @probes = do {
    my $lines = do { local $/; <STDIN> };
    my @probes = do {
        $lines =~ s{/(?:/[^\n]*|\*.*?\*\/)}{}gs;
        $lines =~ /\nprovider\s*quicly\s*{(.*)\n};/s
            or die "failed to locate provider declaration";
        split ';', $1;
    };
    grep {
        ref $_ eq 'ARRAY'
    } map {
        (sub {
            /^\s*probe\s*([A-Za-z0-9_]+)\((.*)\)/s or return;
            my ($name, $args) = ($1, $2);
            my @args = split /\s*,\s*/s, $args;
            for my $arg (@args) {
                $arg =~ /\s*([A-Za-z0-9_]+)$/s or return;
                $arg = [$1, $`]; # name and type
            }
            [$name, \@args];
        })->();
    } @probes;
};

if ($^O eq 'linux') {
    print << 'EOT';

struct st_quicly_conn_t {
    uint32_t dummy[4];
    uint32_t master_id;
};

struct st_quicly_stream_t {
    uint64_t dummy[1];
    int64_t stream_id;
};

struct st_first_octet_t {
    uint8_t b;
};

struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
};

EOT
}

for my $probe (@probes) {
    my @fmt = (sprintf '"type":"%s"', do {
        my $name = $probe->[0];
        normalize_name($name);
    });
    my @ap;
    for (my $i = 0; $i < @{$probe->[1]}; ++$i) {
        my ($name, $type) = @{$probe->[1]->[$i]};
        if ($type eq 'struct st_quicly_conn_t *') {
            push @fmt, '"conn":%u';
            if ($^O eq 'linux') {
                push @ap, '((struct st_quicly_conn_t *)arg' . $i . ')->master_id';
            } else {
                push @ap, '*(uint32_t *)copyin(arg' . $i . ' + 16, 4)';
            }
        } elsif ($type eq 'struct st_quicly_stream_t *') {
            push @fmt, '"stream-id":%d';
            if ($^O eq 'linux') {
                push @ap, '*((struct st_quicly_stream_t *)arg' . $i . ')->stream_id';
            } else {
                push @ap, '*(int64_t *)copyin(arg' . $i . ' + 8, 8)';
            }
        } elsif ($type eq 'struct quicly_rtt_t *') {
            push @fmt, map {qq("$_":\%u)} qw(min-rtt smoothed-rtt latest-rtt);
            if ($^O eq 'linux') {
                push @ap, map{"((struct quicly_rtt_t *)arg$i)->$_"} qw(minimum smoothed latest);
            } else {
                push @ap, map{"*(uint32_t *)copyin(arg$i + $_, 4)"} qw(0 4 12);
            }
        } else {
            $name = 'time'
                if $name eq 'at';
            $name = normalize_name($name);
            if ($type =~ /^(?:unsigned\s|uint([0-9]+)_t|size_t)/) {
                if ($^O eq 'linux') {
                    push @fmt, qq!"$name":\%@{[($1 && $1 == 64) || $type eq 'size_t' ? 'lu' : 'u']}!;
                    push @ap, "arg$i";
                } else {
                    push @fmt, qq!"$name":\%lu!;
                    push @ap, "(uint64_t)arg$i";
                }
            } elsif ($type =~ /^int(?:([0-9]+)_t|)$/) {
                push @fmt, qq!"$name":\%@{[$1 && $1 == 64 ? 'ld' : 'd']}!;
                push @ap, "arg$i";
            } elsif ($type =~ /^const\s+char\s+\*$/) {
                push @fmt, qq!"$name":"\%s"!;
                if ($^O eq 'linux') {
                    push @ap, "str(arg$i)";
                } else {
                    push @ap, "arg$i ? copyinstr(arg$i) : \"\"";
                }
            } elsif ($type =~ /^const\s+void\s+\*$/) {
                # skip const void *
            } else {
                die "can't handle type: $type";
            }
        }
    }
    if ($probe->[0] eq 'receive') {
        splice @fmt, -1, 0, '"first-octet":%u';
        if ($^O eq 'linux') {
            splice @ap, -1, 0, '*((struct st_first_octet_t *)arg3)->b';
        } else {
            splice @ap, -1, 0, '*(uint8_t *)copyin(arg3, 1)';
        }
    }
    if ($^O eq 'linux') {
        $fmt[0] = "{$fmt[0]";
        $fmt[-1] .= "}\\n";
        print << "EOT";
usdt::quicly:$probe->[0] {
EOT
        my @args = (shift(@fmt));
        while (@fmt && @args <= 7) {
            if (length "$args[0], $fmt[0]" >= 64) {
                $args[0] =~ s/\"/\\\"/g;
                print "    printf(\"@{[shift @args]}\", @{[join ', ', @args]});\n";
                @args = ('');
            }
            $args[0] .= ", " . shift @fmt;
            push @args, shift @ap;
        }
        $args[0] =~ s/\"/\\\"/g;
        print << "EOT";
    printf("@{[shift @args]}", @{[ join ', ', @args]});
}
EOT
    } else {
        my $fmt = join ', ', @fmt;
        $fmt =~ s/\"/\\\"/g;
        print << "EOT";
quicly\$target:::$probe->[0] {
    printf("\\n\{$fmt\}", @{[join ', ', @ap]});
}
EOT
    }
}

sub normalize_name {
    my $n = shift;
    $n =~ tr/_/-/;
    $n;
}
