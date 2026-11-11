package t::RawConnection;

use strict;
use warnings;
use Fcntl qw(F_SETFD FD_CLOEXEC);
use File::Temp;
use IO::Socket::INET;
use JSON qw(decode_json);
use Socket qw(SOCK_DGRAM IPPROTO_UDP inet_aton pack_sockaddr_in);

sub new {
    my ($klass, $host, $port, %opts) = @_;
    my $cli = delete $opts{cli}
        or die "cli option is mandatory";

    my $self = bless {
        cli                  => $cli,
        sock                 => do {
            IO::Socket::INET->new(
                Type  => SOCK_DGRAM,
                Proto => IPPROTO_UDP,
            ) or die "failed to open socket:$!";
        },
        peeraddr            => pack_sockaddr_in($port, inet_aton($host)),
        pn                  => 256, # whatever large enough to avoid collision with those used during the handshake
        largest_pn_received => -1,
    }, $klass;

    # perform handshake and obtain connection parameters
    fcntl($self->{sock}, F_SETFD, 0)
        or die "failed to drop FD_CLOEXEC:$!";
    my @alpn = map { ("-a", $_) } @{ $opts{alpn} // [] };
    open(
        my $fh,
        "-|",
        $cli, "--sockfd", fileno($self->{sock}), @alpn, qw(-y aes128gcmsha256 -e /dev/stdout --exit-after-handshake),
        $host, $port,
    ) or die "failed to spawn $cli:$!";
    fcntl($self->{sock}, F_SETFD, FD_CLOEXEC)
        or die "failed to re-add FD_CLOEXEC:$!";
    while (my $line = <$fh>) {
        chomp $line;
        my $event = decode_json $line;
        if ($event->{type} eq 'receive') {
            if (!defined $self->{server_cid}) {
                $event->{bytes} =~ /^..0000000100([0-9a-f]{2})/
                    or die "invalid CID lengths found in packet:$event->{bytes}";
                my $cid_len = hex $1;
                $event->{bytes} =~ /^..0000000100..(.{@{[$cid_len * 2]}})/
                    or die "invalid CID found in packet:$event->{bytes}";
                $self->{server_cid} = pack "H*", $1;
                $self->{server_cid_len} = $cid_len;
            }
        } elsif ($event->{type} eq 'crypto_update_secret' && $event->{epoch} == 3) {
            ($event->{is_enc} ? $self->{enc_secret} : $self->{dec_secret}) = $event->{secret};
        } elsif ($event->{type} eq 'packet_received') {
            $self->{largest_pn_received} = $event->{pn}
                if $self->{largest_pn_received} < $event->{pn};
        }
    }
    close $fh
        or die "$cli failed with exit status:$?";

    $self;
}

sub largest_pn_received {
    my $self = shift;
    $self->{largest_pn_received};
}

sub send {
    my ($self, $payload) = @_;

    my $cleartext = join("",
        "\x41",                    # first byte (pnlen=2)
        $self->{server_cid},
        pack("n", ++$self->{pn}),
        $payload,
        "\0" x 20,                 # space enough for header protection entropy and AEAD tag,
    );
    my $encrypted = $self->transform_packet(1, $cleartext);
    $self->{sock}->send($encrypted, 0, $self->{peeraddr});
}

sub receive {
    my $self = shift;

    recv($self->{sock}, my $encrypted, 1500, 0)
        or return;
    $self->transform_packet(0, $encrypted);
}

sub transform_packet {
    my ($self, $is_enc, $input) = @_;
    my $tmpfh = File::Temp->new();

    print $tmpfh $input;
    $tmpfh->flush();

    my $mode = $is_enc ? "enc" : "dec";
    my $dcid_len = $is_enc ? $self->{server_cid_len} : 0;
    my $cli = $self->{cli};
    open my $fh, "$cli --${mode}rypt-packet @{[$self->{$mode . '_secret'}]}:$dcid_len < $tmpfh |"
        or die "failed to run $cli:$!";
    local $/;
    <$fh>;
}

1;
