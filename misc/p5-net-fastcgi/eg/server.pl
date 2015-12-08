#!/usr/bin/perl
use strict;
use warnings;

use IO::Socket             qw[];
use PerlIO::scalar         qw[];
use Net::FastCGI::Constant qw[:type :role :flag :protocol_status FCGI_NULL_REQUEST_ID];
use Net::FastCGI::IO       qw[read_record write_record write_stream];
use Net::FastCGI::Protocol qw[build_end_request_body
                              build_unknown_type_body
                              build_params
                              parse_begin_request_body
                              parse_params
                              dump_record_body ];

my %FCGI_VALUES = (
    FCGI_MAX_CONNS   => 1,  # maximum number of concurrent transport connections this application will accept
    FCGI_MAX_REQS    => 1,  # maximum number of concurrent requests this application will accept
    FCGI_MPXS_CONNS  => 0,  # multiplex
);

sub handle_connection {
    my ($socket, $on_request) = @_;

    my ( $current_id,  # id of the request we are currently processing
         $stdin,       # buffer for stdin
         $stdout,      # buffer for stdout
         $stderr,      # buffer for stderr
         $params,      # buffer for params (environ)
         $keep_conn ); # more requests on this connection?

    ($current_id, $stdin, $stdout, $stderr, $params) = (0, '', '', '', '', '');

    use warnings FATAL => 'Net::FastCGI::IO';

    while () {
        my ($type, $request_id, $content) = read_record($socket)
          or last;

        if ($request_id == FCGI_NULL_REQUEST_ID) {
            if ($type == FCGI_GET_VALUES) {
                my $values = parse_params($content);
                my %params = map { $_ => $FCGI_VALUES{$_} }
                            grep { exists $FCGI_VALUES{$_} }
                            keys %{$values};
                write_record($socket, FCGI_GET_VALUES_RESULT,
                    FCGI_NULL_REQUEST_ID, build_params(\%params));
            }
            else {
                write_record($socket, FCGI_UNKNOWN_TYPE,
                    FCGI_NULL_REQUEST_ID, build_unknown_type_body($type));
            }
        }
        elsif ($type == FCGI_BEGIN_REQUEST) {
            my ($role, $flags) = parse_begin_request_body($content);
            if ($current_id || $role != FCGI_RESPONDER) {
                my $status = $current_id ? FCGI_CANT_MPX_CONN : FCGI_UNKNOWN_ROLE;
                write_record($socket, FCGI_END_REQUEST, $request_id,
                    build_end_request_body(0, $status));
            }
            else {
                $current_id = $request_id;
                $keep_conn  = ($flags & FCGI_KEEP_CONN);
            }
        }
        elsif ($request_id != $current_id) {
            # ignore inactive requests (FastCGI Specification 3.3)
        }
        elsif ($type == FCGI_ABORT_REQUEST) {
            $current_id = 0;
            ($stdin, $stdout, $stderr, $params) = ('', '', '', '');
        }
        elsif ($type == FCGI_PARAMS) {
            $params .= $content;
        }
        elsif ($type == FCGI_STDIN) {
            $stdin .= $content;

            unless (length $content) {
                # process request

                open(my $in, '<', \$stdin)
                  || die(qq/Couldn't open scalar as a file handle: $!/);

                open(my $out, '>', \$stdout)
                  || die(qq/Couldn't open scalar as a file handle: $!/);

                open(my $err, '>', \$stderr)
                  || die(qq/Couldn't open scalar as a file handle: $!/);

                my $environ = parse_params($params);

                eval {
                    $on_request->($environ, $in, $out, $err);
                };

                if (my $e = $@) {
                    warn(qq/Caught an exception in request callback: '$e'/);
                    $stdout = "Status: 500 Internal Server Error\n\n";
                }

                write_stream($socket, FCGI_STDOUT, $current_id, $stdout, 1);
                write_stream($socket, FCGI_STDERR, $current_id, $stderr, 1)
                  if length $stderr;
                write_record($socket, FCGI_END_REQUEST, $current_id,
                    build_end_request_body(0, FCGI_REQUEST_COMPLETE));

                # prepare for next request
                $current_id = 0;
                ($stdin, $stdout, $stderr, $params) = ('', '', '', '');

                last unless $keep_conn;
            }
        }
        else {
            warn(q/Received an unexpected record: / .
                dump_record_body($type, $request_id, $content));
        }
    }

    (!$current_id)
      || warn(q/Client prematurely closed connection/);
}

sub handle_request {
    my ($env, $stdin, $stdout, $stderr) = @_;

    $env->{GATEWAY_INTERFACE} ||= 'CGI/1.1';

    local *ENV    = $env;
    local *STDIN  = $stdin;
    local *STDOUT = $stdout;
    local *STDERR = $stderr;

    print "Status: 200 OK\n";
    print "Content-Type: text/plain\n\n";
    print map { sprintf "%-25s => %s\n", $_, $ENV{$_} } sort keys %ENV;
}

my $addr = shift(@ARGV) || 'localhost:3000';

my $socket = IO::Socket::INET->new(
    Listen    => 5,
    LocalAddr => $addr,
    Reuse     => 1,
) or die(qq/Couldn't create INET listener socket <$addr>: '$!'./);

print STDERR "Listening for connections on <$addr>\n";

while () {
    my $connection = $socket->accept
      or last;

    eval {
        handle_connection($connection, \&handle_request);
    };

    if (my $e = $@) {
        warn(qq/Caught an exception in handle_connection(): '$e'/);
    }

    close $connection;
}

