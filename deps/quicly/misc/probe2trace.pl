#! /bin/sh
exec perl -x $0 "$@"
#! perl

use strict;
use warnings;
use Getopt::Long;

my $arch = $^O;

GetOptions("arch=s" => \$arch)
    or die "invalid command option\n";



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

# emit preamble
if ($arch eq 'linux') {
    print << 'EOT';
#include <stdint.h>

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
} elsif ($arch eq 'darwin') {
} else {
    print << 'EOT';
#ifndef embedded_probes_h
#define embedded_probes_h

extern FILE *quicly_trace_fp;
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
            if ($arch eq 'linux') {
                push @ap, '((struct st_quicly_conn_t *)arg' . $i . ')->master_id';
            } elsif ($arch eq 'darwin') {
                push @ap, '*(uint32_t *)copyin(arg' . $i . ' + 16, 4)';
            } else {
                push @ap, "((struct _st_quicly_conn_public_t *)arg$i)->master_id.master_id";
            }
        } elsif ($type eq 'struct st_quicly_stream_t *') {
            push @fmt, '"stream-id":%d';
            if ($arch eq 'linux') {
                push @ap, '*((struct st_quicly_stream_t *)arg' . $i . ')->stream_id';
            } elsif ($arch eq 'darwin') {
                push @ap, '*(int64_t *)copyin(arg' . $i . ' + 8, 8)';
            } else {
                push @ap, "(int)arg${i}->stream_id";
            }
        } elsif ($type eq 'struct quicly_rtt_t *') {
            push @fmt, map {qq("$_":\%u)} qw(min-rtt smoothed-rtt latest-rtt);
            if ($arch eq 'linux') {
                push @ap, map{"((struct quicly_rtt_t *)arg$i)->$_"} qw(minimum smoothed latest);
            } elsif ($arch eq 'darwin') {
                push @ap, map{"*(uint32_t *)copyin(arg$i + $_, 4)"} qw(0 4 12);
            } else {
                push @ap, map{"arg${i}->$_"} qw(minimum smoothed latest);
            }
        } else {
            $name = 'time'
                if $name eq 'at';
            $name = normalize_name($name);
            if ($type =~ /^(?:unsigned\s|uint([0-9]+)_t|size_t)/) {
                if ($arch eq 'linux') {
                    push @fmt, qq!"$name":\%@{[($1 && $1 == 64) || $type eq 'size_t' ? 'lu' : 'u']}!;
                    push @ap, "arg$i";
                } elsif ($arch eq 'darwin') {
                    push @fmt, qq!"$name":\%lu!;
                    push @ap, "(uint64_t)arg$i";
                } else {
                    push @fmt, qq!"$name":\%llu!;
                    push @ap, "(unsigned long long)arg$i";
                }
            } elsif ($type =~ /^int(?:([0-9]+)_t|)$/) {
                if ($arch ne 'embedded') {
                    push @fmt, qq!"$name":\%@{[$1 && $1 == 64 ? 'ld' : 'd']}!;
                    push @ap, "arg$i";
                } else {
                    push @fmt, qq!"$name":\%lld!;
                    push @ap, "(long long)arg$i";
                }
            } elsif ($type =~ /^const\s+char\s+\*$/) {
                push @fmt, qq!"$name":"\%s"!;
                if ($arch eq 'linux') {
                    push @ap, "str(arg$i)";
                } elsif ($arch eq 'darwin') {
                    push @ap, "arg$i ? copyinstr(arg$i) : \"\"";
                } else {
                    push @ap, "arg$i";
                }
            } elsif ($type =~ /\s+\*$/) {
                # emit the address for other pointers
                push @fmt, qq!"name":"0x%llx"!;
                push @ap, "(unsigned long long)arg$i";
            } else {
                die "can't handle type: $type";
            }
        }
    }
    if ($probe->[0] eq 'receive') {
        splice @fmt, -1, 0, '"first-octet":%u';
        if ($arch eq 'linux') {
            splice @ap, -1, 0, '*((struct st_first_octet_t *)arg3)->b';
        } elsif ($arch eq 'darwin') {
            splice @ap, -1, 0, '*(uint8_t *)copyin(arg3, 1)';
        } else {
            splice @ap, -1, 0, '*(uint8_t *)arg3';
        }
    }
    if ($arch eq 'linux') {
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
    } elsif ($arch eq 'darwin') {
        my $fmt = join ', ', @fmt;
        $fmt =~ s/\"/\\\"/g;
        print << "EOT";
quicly\$target:::$probe->[0] {
    printf("\\n\{$fmt\}", @{[join ', ', @ap]});
}
EOT
    } else {
        my $fmt = join ', ', @fmt;
        $fmt =~ s/\"/\\\"/g;
        print << "EOT";

#define QUICLY_@{[ uc $probe->[0] ]}_ENABLED() (quicly_trace_fp != NULL)

static void QUICLY_@{[ uc $probe->[0] ]}(@{[ join ", ", map { "$probe->[1]->[$_]->[1] arg$_" } 0..$#{$probe->[1]}]})
{
    fprintf(quicly_trace_fp, "{$fmt}\\n", @{[join ', ', @ap]});
}
EOT
    }
}

if ($arch eq 'embedded') {
print << 'EOT';

#endif
EOT
}

sub normalize_name {
    my $n = shift;
    $n =~ tr/_/-/;
    $n;
}
