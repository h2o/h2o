package Net::FastCGI::IO;
use strict;
use warnings;
use warnings::register;

use Carp                   qw[];
use Errno                  qw[EBADF EINTR EPIPE];
use Net::FastCGI::Constant qw[FCGI_HEADER_LEN];
use Net::FastCGI::Protocol qw[build_header build_record build_stream
                              parse_header parse_record];

BEGIN {
    our $VERSION   = '0.14';
    our @EXPORT_OK = qw[ can_read
                         can_write
                         read_header
                         read_record
                         write_header
                         write_record
                         write_stream ];

    our %EXPORT_TAGS = ( all => \@EXPORT_OK );

    require Exporter;
    *import = \&Exporter::import;

    eval q<use Time::HiRes 'time'>;
}

*throw = \&Carp::croak;

sub read_header {
    @_ == 1 || throw(q/Usage: read_header(fh)/);
    my ($fh) = @_;

    my $len = FCGI_HEADER_LEN;
    my $off = 0;
    my $buf;

    while ($len) {
        my $r = sysread($fh, $buf, $len, $off);
        if (defined $r) {
            last unless $r;
            $len -= $r;
            $off += $r;
        }
        elsif ($! != EINTR) {
            warnings::warn(qq<FastCGI: Could not read FCGI_Header: '$!'>)
              if warnings::enabled;
            return;
        }
    }
    if ($len) {
        $! = $off ? EPIPE : 0;
        warnings::warn(q<FastCGI: Could not read FCGI_Header: Unexpected end of stream>)
          if $off && warnings::enabled;
        return;
    }
    return parse_header($buf);
}

sub write_header {
    @_ == 5 || throw(q/Usage: write_header(fh, type, request_id, content_length, padding_length)/);
    my $fh = shift;

    my $buf = &build_header;
    my $len = FCGI_HEADER_LEN;
    my $off = 0;

    while () {
        my $r = syswrite($fh, $buf, $len, $off);
        if (defined $r) {
            $len -= $r;
            $off += $r;
            last unless $len;
        }
        elsif ($! != EINTR) {
            warnings::warn(qq<FastCGI: Could not write FCGI_Header: '$!'>)
              if warnings::enabled;
            return undef;
        }
    }
    return $off;
}

sub read_record {
    @_ == 1 || throw(q/Usage: read_record(fh)/);
    my ($fh) = @_;

    my $len = FCGI_HEADER_LEN;
    my $off = 0;
    my $buf;

    while ($len) {
        my $r = sysread($fh, $buf, $len, $off);
        if (defined $r) {
            last unless $r;
            $len -= $r;
            $off += $r;
            if (!$len && $off == FCGI_HEADER_LEN) {
                $len = vec($buf, 2, 16)  # Content Length
                     + vec($buf, 6,  8); # Padding Length
            }
        }
        elsif ($! != EINTR) {
            warnings::warn(qq<FastCGI: Could not read FCGI_Record: '$!'>)
              if warnings::enabled;
            return;
        }
    }
    if ($len) {
        $! = $off ? EPIPE : 0;
        warnings::warn(q<FastCGI: Could not read FCGI_Record: Unexpected end of stream>)
          if $off && warnings::enabled;
        return;
    }
    return parse_record($buf);
}

sub write_record {
    @_ == 4 || @_ == 5 || throw(q/Usage: write_record(fh, type, request_id [, content])/);
    my $fh = shift;

    my $buf = &build_record;
    my $len = length $buf;
    my $off = 0;

    while () {
        my $r = syswrite($fh, $buf, $len, $off);
        if (defined $r) {
            $len -= $r;
            $off += $r;
            last unless $len;
        }
        elsif ($! != EINTR) {
            warnings::warn(qq<FastCGI: Could not write FCGI_Record: '$!'>)
              if warnings::enabled;
            return undef;
        }
    }
    return $off;
}

sub write_stream {
    @_ == 4 || @_ == 5 || throw(q/Usage: write_stream(fh, type, request_id, content [, terminate])/);
    my $fh = shift;

    my $buf = &build_stream;
    my $len = length $buf;
    my $off = 0;

    while () {
        my $r = syswrite($fh, $buf, $len, $off);
        if (defined $r) {
            $len -= $r;
            $off += $r;
            last unless $len;
        }
        elsif ($! != EINTR) {
            warnings::warn(qq<FastCGI: Could not write FCGI_Record stream: '$!'>)
              if warnings::enabled;
            return undef;
        }
    }
    return $off;
}

sub can_read (*$) {
    @_ == 2 || throw(q/Usage: can_read(fh, timeout)/);
    my ($fh, $timeout) = @_;

    my $fd = fileno($fh);
    unless (defined $fd && $fd >= 0) {
        $! = EBADF;
        return undef;
    }

    my $initial = time;
    my $pending = $timeout;
    my $nfound;

    vec(my $fdset = '', $fd, 1) = 1;

    while () {
        $nfound = select($fdset, undef, undef, $pending);
        if ($nfound == -1) {
            return undef unless $! == EINTR;
            redo if !$timeout || ($pending = $timeout - (time - $initial)) > 0;
            $nfound = 0;
        }
        last;
    }
    $! = 0;
    return $nfound;
}

sub can_write (*$) {
    @_ == 2 || throw(q/Usage: can_write(fh, timeout)/);
    my ($fh, $timeout) = @_;

    my $fd = fileno($fh);
    unless (defined $fd && $fd >= 0) {
        $! = EBADF;
        return undef;
    }

    my $initial = time;
    my $pending = $timeout;
    my $nfound;

    vec(my $fdset = '', $fd, 1) = 1;

    while () {
        $nfound = select(undef, $fdset, undef, $pending);
        if ($nfound == -1) {
            return undef unless $! == EINTR;
            redo if !$timeout || ($pending = $timeout - (time - $initial)) > 0;
            $nfound = 0;
        }
        last;
    }
    $! = 0;
    return $nfound;
}

1;

