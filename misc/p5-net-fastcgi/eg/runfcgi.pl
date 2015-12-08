#!/usr/bin/perl
# This program is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
#  (C) Paul Evans, 2010 -- leonerd@leonerd.org.uk

use strict;
use warnings;

use Getopt::Long;

use Net::FastCGI::IO qw( read_record );
use Net::FastCGI::Constant qw( :common :type :role );
use Net::FastCGI::Protocol qw(
   build_begin_request_body
   build_params
   parse_end_request_body
);

sub write_record
{
   Net::FastCGI::IO::write_record(@_) or
      die "Cannot write_record - $!";
}

my %env = (
   REQUEST_METHOD  => "GET",
   SCRIPT_NAME     => "",
   SERVER_NAME     => "server",
   SERVER_PORT     => 80,
   SERVER_PROTOCOL => "HTTP/1.1",
);

my $stdin_from;
my $filter_stdout;

sub usage
{
   print <<"EOF";
$0 [options] CONNECT URL

Runs the FastCGI found at CONNECT, as if it had received the URL

CONNECT may be any of

  exec:PATH             Execute as a child process with socket on STDIN
  unix:PATH             Find a UNIX socket on the given path
  tcp:HOST:PORT         Connect to the given port on the given host
  HOST:PORT              as above

options may be:

      --body            Print just the HTTP response body
      --no-body         Print just the HTTP response headers without the body
  -m, --method METHOD   Use the specified method (default "GET")
  -p, --post            Method is POST, pass STDIN
      --put             Method is PUT, pass STDIN
      --stdin PATH      Read STDIN from specified path, "-" means real script

EOF
}

GetOptions(
   'body' => sub {
      defined $filter_stdout and die "Cannot --no-body and --body\n";
      $filter_stdout = "body";
   },
   'no-body' => sub {
      defined $filter_stdout and die "Cannot --no-body and --body\n";
      $filter_stdout = "headers";
   },
   'm|method=s' => \$env{REQUEST_METHOD},
   'p|post' => sub {
      $env{REQUEST_METHOD} = "POST";
      $stdin_from = "-";
   },
   'put' => sub {
      $env{REQUEST_METHOD} = "PUT";
      $stdin_from = "-";
   },
   'stdin=s' => \$stdin_from,
   'help' => sub { usage; exit(0) },
) or exit(1);

my $connect = shift @ARGV or
   die "Require connection string\n";

my $url = shift @ARGV or
   die "Require a URL";

if( $url =~ s{^http(s?)://([^/:]+)(?::([^/]+))?}{} ) {
   $env{HTTPS} = "on" if $1;
   $env{SERVER_NAME} = $2;
   $env{SERVER_PORT} = $3 || ( $1 ? 443 : 80 );
}

$env{REQUEST_URI} = $url;

my ( $path, $query ) = $url =~ m/^(.*)(?:\?(.*))$/;

$env{PATH_INFO}    = $path;
$env{QUERY_STRING} = $query;

my $socket;

if( $connect =~ m/^unix:(.*)$/ ) {
   my $path = $1;

   require IO::Socket::UNIX;

   $socket = IO::Socket::UNIX->new(
      Peer => $path,
   ) or die "Cannot connect - $!\n";
}
elsif( $connect =~ m/^exec:(.*)$/ ) {
   my $script = $1;

   require IO::Socket::INET;

   my $listener = IO::Socket::INET->new(
      LocalHost => "localhost",
      Listen    => 1,
   ) or die "Cannot listen - $@";

   defined( my $kid = fork ) or die "Cannot fork - $!";
   END { defined $kid and kill TERM => $kid }

   if( $kid == 0 ) {
      close STDIN;
      open STDIN, "<&", $listener or die "Cannot dup $listener to STDIN - $!";

      close $listener;

      exec { $script } $script or die "Cannot exec $script - $!";
   }

   $socket = IO::Socket::INET->new(
      PeerHost => $listener->sockhost,
      PeerPort => $listener->sockport,
   ) or die "Cannot connect - $@";

   close $listener;
}
elsif( $connect =~ m/^(?:tcp:)?(.*):(.+?)$/ ) {
   my $host = $1 || "localhost";
   my $port = $2;

   my $class = eval { require IO::Socket::IP   and "IO::Socket::IP" } ||
               do   { require IO::Socket::INET and "IO::Socket::INET" };

   $socket = $class->new(
      PeerHost => $host,
      PeerPort => $port,
   ) or die "Cannot connect - $@\n";
}
else {
   die "Cannot recognise connection string '$connect'\n";
}

write_record( $socket, FCGI_BEGIN_REQUEST, 1,
   build_begin_request_body( FCGI_RESPONDER, 0 ) );

write_record( $socket, FCGI_PARAMS, 1,
   build_params( \%env ) );

write_record( $socket, FCGI_PARAMS, 1, "" );

if( defined $stdin_from ) {
   my $stdin;

   if( $stdin_from eq "-" ) {
      $stdin = \*STDIN;
   }
   else {
      open $stdin, "<", $stdin_from or die "Cannot open $stdin_from for input - $!";
   }

   while( read( $stdin, my $buffer, 8192 ) ) {
      write_record( $socket, FCGI_STDIN, 1, $buffer );
   }
}

write_record( $socket, FCGI_STDIN, 1, "" );

my $stdout = "";

while(1) {
   my ( $type, $id, $content ) = read_record( $socket )
      or $! and die "Cannot read_record - $!"
      or last;

   if( $type == FCGI_STDOUT ) {
      if( !defined $filter_stdout ) {
         print STDOUT $content;
      }
      elsif( $filter_stdout eq "headers" ) {
         my $oldlen = length $stdout;
         $stdout .= $content;
         if( $stdout =~ m/\r\n\r\n/ ) {
            # Print only the bit we haven't done yet
            print STDOUT substr( $stdout, $oldlen, $+[0] - $oldlen );
            $filter_stdout = 1; # I.e. suppress the lot
         }
         else {
            print STDOUT $content;
         }
      }
      elsif( $filter_stdout eq "body" ) {
         $stdout .= $content;
         if( $stdout =~ m/\r\n\r\n/ ) {
            print STDOUT substr( $stdout, $+[0] );
            $filter_stdout = undef;
         }
      }
   }
   elsif( $type == FCGI_STDERR ) {
      print STDERR $content;
   }
   elsif( $type == FCGI_END_REQUEST ) {
      my ( $app_status, $protocol_status ) = parse_end_request_body( $content );
      exit $app_status;
   }
   else {
      die "Unrecognised FastCGI request type $type\n";
   }
}
