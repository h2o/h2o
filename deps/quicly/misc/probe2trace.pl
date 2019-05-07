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

for my $probe (@probes) {
    my @fmt = (sprintf '"type":"%s"', do {
        my $name = $probe->[0];
        $name =~ s/^quicly_//;
        normalize_name($name);
    });
    my @ap;
    for (my $i = 0; $i < @{$probe->[1]}; ++$i) {
        my ($name, $type) = @{$probe->[1]->[$i]};
        if ($type eq 'struct st_quicly_conn_t *') {
            push @fmt, '"conn":%u';
            push @ap, '*(uint32_t *)copyin(arg' . $i . ' + 16, 4)';
        } elsif ($type eq 'struct st_quicly_stream_t *') {
            push @fmt, '"stream-id":%d';
            push @ap, '*(int64_t *)copyin(arg' . $i . ' + 8, 8)';
        } else {
            $name = 'time'
                if $name eq 'at';
            $name = normalize_name($name);
            if ($type =~ /^(unsigned\s|uint[0-9]+_t|size_t)/) {
                push @fmt, "\"$name\":\%u";
                push @ap, "arg$i";
            } elsif ($type =~ /^int(?:[0-9]+_t|)$/) {
                push @fmt, "\"$name\":\%d";
                push @ap, "arg$i";
            } elsif ($type =~ /^const\s+char\s+\*$/) {
                push @fmt, "\"$name\":\"\%s\"";
                push @ap, "arg$i ? copyinstr(arg$i) : \"\"";
            } elsif ($type =~ /^const\s+void\s+\*$/) {
                # skip const void *
            } else {
                die "can't handle type: $type";
            }
        }
    }
    my $fmt = join ', ', @fmt;
    $fmt =~ s/\"/\\\"/g;
    print << "EOT";
quicly\$target:::$probe->[0] {
    printf("\\n\{$fmt\}", @{[join ', ', @ap]});
}
EOT
}

sub normalize_name {
    my $n = shift;
    $n =~ tr/_/-/;
    $n;
}
