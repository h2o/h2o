#! /bin/sh
exec perl -x $0 "$@"
#! perl

use strict;
use warnings;
use Getopt::Long;

my $arch = $^O;
my %tracer_probes = map { uc($_) => 1 } qw(packet_sent packet_received packet_acked packet_lost packet_decryption_failed pto cc_ack_received cc_congestion quictrace_cc_ack quictrace_cc_lost max_data_send max_data_receive max_stream_data_send max_stream_data_receive streams_blocked_send streams_blocked_receive stream_on_open stream_on_destroy);

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

struct quicly_cc_t {
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t stash;
    uint64_t recovery_end;
};

EOT
} elsif ($arch eq 'darwin') {
} elsif ($arch eq 'embedded') {
    print << 'EOT';
#ifndef embedded_probes_h
#define embedded_probes_h

extern FILE *quicly_trace_fp;
EOT
} else {
    print << 'EOT';
#ifndef callback_probes_h
#define callback_probes_h

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
            if ($arch ne 'tracer') {
                push @fmt, '"conn":%u';
                if ($arch eq 'linux') {
                    push @ap, "arg$i" . ' != NULL ? ((struct st_quicly_conn_t *)arg' . $i . ')->master_id : 0';
                } elsif ($arch eq 'darwin') {
                    push @ap, "arg$i" . ' != NULL ? *(uint32_t *)copyin(arg' . $i . ' + 16, 4) : 0';
                } else {
                    push @ap, "arg$i != NULL ? ((struct _st_quicly_conn_public_t *)arg$i)->local.cid_set.plaintext.master_id : 0";
                }
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
        } elsif ($type eq 'struct st_quicly_stats_t *') {
            # build an array of [field-names => type-specifiers]
            my @fields;
            push @fields, map {["rtt.$_" => '%u']} qw(minimum smoothed variance);
            push @fields, map {["cc.$_" => '%u']} qw(cwnd ssthresh cwnd_initial cwnd_exiting_slow_start cwnd_minimum cwnd_maximum num_loss_episodes);
            push @fields, map {["num_packets.$_" => $arch eq 'embedded' ? '%" PRIu64 "' : '%llu']} qw(sent ack_received lost lost_time_threshold late_acked received decryption_failed);
            push @fields, map {["num_bytes.$_" => $arch eq 'embedded' ? '%" PRIu64 "' : '%llu']} qw(sent received);
            for my $container (qw(num_frames_sent num_frames_received)) {
                push @fields, map{["$container.$_" => $arch eq 'embedded' ? '%" PRIu64 "' : '%llu']} qw(padding ping ack reset_stream stop_sending crypto new_token stream max_data max_stream_data max_streams_bidi max_streams_uni data_blocked stream_data_blocked streams_blocked new_connection_id retire_connection_id path_challenge path_response transport_close application_close handshake_done ack_frequency);
            }
            push @fields, ["num_ptos" => $arch eq 'embedded' ? '%" PRIu64 "' : '%llu'];
            # generate @fmt, @ap
            push @fmt, map {my $n = $_->[0]; $n =~ tr/./_/; sprintf '"%s":%s', $n, $_->[1]} @fields;
            if ($arch eq 'linux') {
                push @ap, map{"((struct st_quicly_stats_t *)arg$i)->" . $_->[0]} @fields;
            } else {
                push @ap, map{"arg${i}->" . $_->[0]} @fields;
            }
            # special handling of cc.type
            push @fmt, '"cc_type":"%s"';
            if ($arch eq 'linux') {
                push @ap, "str((struct st_quicly_stats_t *)arg$i)->cc.type->name)";
            } elsif ($arch eq 'darwin') {
                push @ap, "copyinstr(str(arg${i}->cc.type->name))";
            } else {
                push @ap, "arg${i}->cc.type->name";
            }
        } else {
            $name = 'time'
                if $name eq 'at';
            $name = normalize_name($name);
            if ($type =~ /^(?:unsigned|uint([0-9]+)_t|size_t)$/) {
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
                if ($arch ne 'embedded' && $arch ne 'tracer') {
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
                push @fmt, qq!"$name":"0x%llx"!;
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
        $fmt =~ s/\%\\" ([A-Za-z0-9]+) \\"/\%" $1 "/g; # nasty hack to revert `"` -> `\"` right above for PRItNN
        my $params = join ", ", map { "$probe->[1]->[$_]->[1] arg$_" } 0..$#{$probe->[1]};
        if ($arch eq 'embedded') {
            print << "EOT";

#define QUICLY_@{[ uc $probe->[0] ]}_ENABLED() (quicly_trace_fp != NULL)

static void QUICLY_@{[ uc $probe->[0] ]}($params)
{
    fprintf(quicly_trace_fp, "{$fmt}\\n", @{[join ', ', @ap]});
}
EOT
        } else {
            # callback probes, the ones not specified are no-op
            if ($tracer_probes{uc $probe->[0]}) {
                print << "EOT";

static inline void QUICLY_TRACER_@{[ uc $probe->[0] ]}($params)
{
    if (arg0->super.tracer.cb != NULL)
        arg0->super.tracer.cb(arg0->super.tracer.ctx, "{$fmt}\\n", @{[join ', ', @ap]});
}
EOT
            } else {
                print << "EOT";

#define QUICLY_TRACER_@{[uc $probe->[0] ]}(...)
EOT
            }
        }
    }
}

if ($arch eq 'embedded' || $arch eq 'tracer') {
print << 'EOT';

#endif
EOT
}

sub normalize_name {
    my $n = shift;
    $n =~ tr/_/-/;
    $n;
}
