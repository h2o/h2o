#! /usr/bin/perl

use strict;
use warnings;
use File::Basename qw(dirname);
use IO::Socket::UNIX;
use Net::FastCGI;
use Net::FastCGI::Constant qw(:common :type :flag :role :protocol_status);
use Net::FastCGI::IO qw(:all);
use Net::FastCGI::Protocol qw(:all);
use POSIX qw(:sys_wait_h getcwd);
use Socket qw(SOMAXCONN SOCK_STREAM);

my $master_pid = $$;
my %child_procs;

$SIG{CHLD} = sub {};
$SIG{HUP} = sub {};
$SIG{TERM} = sub {
    if ($$ == $master_pid) {
        kill "TERM", $_
            for sort keys %child_procs;
    }
    exit 0;
};

my $base_dir = getcwd;
chdir "/"
    or die "failed to chdir to /:$!";

my $listen_sock;
if (-S STDIN) {
    $listen_sock = IO::Socket::UNIX->new;
    $listen_sock->fdopen(fileno(STDIN), "w")
        or die "failed to open unix socket:$!";
} else {
    my $sockpath = $ENV{FASTCGI_CGI_SOCKET}
        or die "STDIN is not a socket, and FASTCGI_CGI_SOCKET is not defined";
    unlink $sockpath;
    $listen_sock = IO::Socket::UNIX->new(
        Listen => SOMAXCONN,
        Local  => $sockpath,
        Type   => SOCK_STREAM,
    ) or die "failed to create unix socket at $sockpath:$!";
}

while (1) {
    if (my $sock = $listen_sock->accept) {
        my $pid = fork;
        die "fork failed:$!"
            unless defined $pid;
        if ($pid == 0) {
            close $listen_sock;
            handle_connection($sock);
            exit 0;
        }
        $sock->close;
        $child_procs{$pid} = 1;
    }
    my $kid = waitpid(-1, WNOHANG);
    if ($kid > 0) {
        delete $child_procs{$kid};
    }
}

sub handle_connection {
    my $sock = shift;
    my ($type, $req_id, $content);
    my $cur_req_id;
    my $params = "";
    my $input_fh;

    # wait for FCGI_BEGIN_REQUEST
    ($type, $req_id, $content) = fetch_record($sock);
    die "expected FCGI_BEGIN_REQUEST, but got $type"
        unless $type == FCGI_BEGIN_REQUEST;
    my ($role, $flags) = parse_begin_request_body($content);
    die "unexpected role:$role"
        unless $role == FCGI_RESPONDER;
    $cur_req_id = $req_id;

    # accumulate FCGI_PARAMS
    while (1) {
        ($type, $req_id, $content) = fetch_record($sock);
        last if $type != FCGI_PARAMS;
        die "unexpected request id"
            if $cur_req_id != $req_id;
        $params .= $content;
    }
    my $env = parse_params($params);
    die "SCRIPT_FILENAME not defined"
        unless $env->{SCRIPT_FILENAME};
    $env->{SCRIPT_FILENAME} = "$base_dir/$env->{SCRIPT_FILENAME}"
        if $env->{SCRIPT_FILENAME} !~ m{^/};

    # accumulate FCGI_STDIN
    while (1) {
        die "received unexpected record: $type"
            if $type != FCGI_STDIN;
        last if length $content == 0;
        if (!$input_fh) {
            $input_fh = tempfile()
                or die "failed to create temporary file:$!";
        }
        print $input_fh $content;
    }
    if (!$input_fh) {
        open $input_fh, "<", "/dev/null"
            or die "failed to open /dev/null:$!";
    }

    # create pipes for stdout and stderr
    pipe(my $stdout_rfh, my $stdout_wfh)
        or die "pipe failed:$!";
    pipe(my $stderr_rfh, my $stderr_wfh)
        or die "pipe failed:$!";

    # fork the CGI application
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        close $sock;
        close $stdout_rfh;
        close $stderr_rfh;
        open STDERR, ">&", $stderr_wfh
            or die "failed to dup STDERR";
        open STDIN, "<&", $input_fh
            or die "failed to dup STDIN";
        open STDOUT, ">&", $stdout_wfh
            or die "failed to dup STDOUT";
        close $stderr_wfh;
        close $input_fh;
        close $stdout_wfh;
        $ENV{$_} = $env->{$_}
            for sort keys %$env;
        chdir dirname($env->{SCRIPT_FILENAME});
        exec $env->{SCRIPT_FILENAME};
        exit 111;
    }
    close $stdout_wfh;
    close $stderr_wfh;

    # send response
    while ($stdout_rfh || $stderr_rfh) {
        my $rin = '';
        vec($rin, fileno $stdout_rfh, 1) = 1
            if $stdout_rfh;
        vec($rin, fileno $stderr_rfh, 1) = 1
            if $stderr_rfh;
        if (select($rin, undef, undef, undef) <= 0) {
            next;
        }
        if ($stdout_rfh && vec($rin, fileno $stdout_rfh, 1)) {
            transfer($sock, FCGI_STDOUT, $cur_req_id, $stdout_rfh)
                or undef $stdout_rfh;
        }
        if ($stderr_rfh && vec($rin, fileno $stderr_rfh, 1)) {
            transfer($sock, FCGI_STDERR, $cur_req_id, $stderr_rfh)
                or undef $stderr_rfh;
        }
    }

    # close
    write_record($sock, FCGI_END_REQUEST, $cur_req_id,  build_end_request_body(0, FCGI_REQUEST_COMPLETE));
    close $sock;

    # wait for child process to die
    while (waitpid($pid, 0) != $pid) {
    }
}

sub fetch_record {
    my $sock = shift;
    my ($type, $req_id, $content) = read_record($sock)
      or die "failed to read FCGI record:$!";
    die "unexpected request id:null"
        if $req_id == FCGI_NULL_REQUEST_ID;
    ($type, $req_id, $content);
}

sub transfer {
    my ($sock, $type, $req_id, $fh) = @_;
    my $buf;

    while (1) {
        my $ret = sysread $fh, $buf, 61440;
        next if (!defined $ret) && $! == Errno::EINTR;
        return undef
            unless $ret;
        last;
    }
    write_record($sock, $type, $req_id, $buf)
        or die "failed to write FCGI response:$!";
    return 1;
}
