#!/usr/bin/perl

# Read datagrams from input files and send them to a specified server

use strict;
use warnings;
use IO::File;
use IO::Socket;

if (@ARGV < 3) {
	print STDERR "Usage: $0 [server] [port] [input...]\n";
	exit 1;
}

my $server = shift @ARGV;
my $port = shift @ARGV;

my $sock = IO::Socket::INET->new(
	Type     => SOCK_DGRAM,
	Proto    => 'udp',
	PeerAddr => $server,
	PeerPort => $port,
) or die "Failed to create a UDP socket: $!";

for my $f (@ARGV) {
	my $fh = IO::File->new($f, "r") or die "Failed to open file: $f: $!";
	my $read = $fh->read(my $dgram, 1500); # 1500 bytes must be enough to store the entire datagram at the moment
	undef $fh;
	my $sent = $sock->send($dgram) or die "Failed to send a datagram: $!";
	if ($read != $sent) {
		die "$read bytes read but $sent bytes sent";
	}
}

$sock->close();
