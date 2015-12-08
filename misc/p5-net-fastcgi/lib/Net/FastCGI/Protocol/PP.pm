package Net::FastCGI::Protocol::PP;
use strict;
use warnings;

use Carp                   qw[];
use Net::FastCGI::Constant qw[:all];

BEGIN {
    our $VERSION   = '0.14';
    our @EXPORT_OK = qw[ build_begin_request
                         build_begin_request_body
                         build_begin_request_record
                         build_end_request
                         build_end_request_body
                         build_end_request_record
                         build_header
                         build_params
                         build_record
                         build_stream
                         build_unknown_type_body
                         build_unknown_type_record
                         check_params
                         parse_begin_request_body
                         parse_end_request_body
                         parse_header
                         parse_params
                         parse_record
                         parse_record_body
                         parse_unknown_type_body
                         is_known_type
                         is_management_type
                         is_discrete_type
                         is_stream_type
                         get_record_length
                         get_role_name
                         get_type_name
                         get_protocol_status_name ];

    our %EXPORT_TAGS = ( all => \@EXPORT_OK );

    require Exporter;
    *import = \&Exporter::import;
}

sub TRUE  () { !!1 }
sub FALSE () { !!0 }

sub ERRMSG_OCTETS    () { q/FastCGI: Insufficient number of octets to parse %s/ }
sub ERRMSG_MALFORMED () { q/FastCGI: Malformed record %s/ }
sub ERRMSG_VERSION   () { q/FastCGI: Protocol version mismatch (0x%.2X)/ }
sub ERRMSG_OCTETS_LE () { q/Invalid Argument: '%s' cannot exceed %u octets in length/ }

sub throw {
    @_ = ( sprintf($_[0], @_[1..$#_]) ) if @_ > 1;
    goto \&Carp::croak;
}

# FCGI_Header

sub build_header {
    @_ == 4 || throw(q/Usage: build_header(type, request_id, content_length, padding_length)/);
    return pack(FCGI_Header, FCGI_VERSION_1, @_);
}

sub parse_header {
    @_ == 1 || throw(q/Usage: parse_header(octets)/);
    (defined $_[0] && length $_[0] >= 8)
      || throw(ERRMSG_OCTETS, q/FCGI_Header/);
    (vec($_[0], 0, 8) == FCGI_VERSION_1)
      || throw(ERRMSG_VERSION, unpack('C', $_[0]));
    return unpack('xCnnCx', $_[0])
      if wantarray;
    my %header; 
       @header{qw(type request_id content_length padding_length)}
         = unpack('xCnnCx', $_[0]);
    return \%header;
}

# FCGI_BeginRequestBody

sub build_begin_request_body {
    @_ == 2 || throw(q/Usage: build_begin_request_body(role, flags)/);
    return pack(FCGI_BeginRequestBody, @_);
}

sub parse_begin_request_body {
    @_ == 1 || throw(q/Usage: parse_begin_request_body(octets)/);
    (defined $_[0] && length $_[0] >= 8)
      || throw(ERRMSG_OCTETS, q/FCGI_BeginRequestBody/);
    return unpack(FCGI_BeginRequestBody, $_[0]);
}

# FCGI_EndRequestBody

sub build_end_request_body {
    @_ == 2 || throw(q/Usage: build_end_request_body(app_status, protocol_status)/);
    return pack(FCGI_EndRequestBody, @_);
}

sub parse_end_request_body {
    @_ == 1 || throw(q/Usage: parse_end_request_body(octets)/);
    (defined $_[0] && length $_[0] >= 8)
      || throw(ERRMSG_OCTETS, q/FCGI_EndRequestBody/);
    return unpack(FCGI_EndRequestBody, $_[0]);
}

# FCGI_UnknownTypeBody

sub build_unknown_type_body {
    @_ == 1 || throw(q/Usage: build_unknown_type_body(type)/);
    return pack(FCGI_UnknownTypeBody, @_);
}

sub parse_unknown_type_body {
    @_ == 1 || throw(q/Usage: parse_unknown_type_body(octets)/);
    (defined $_[0] && length $_[0] >= 8)
      || throw(ERRMSG_OCTETS, q/FCGI_UnknownTypeBody/);
    return unpack(FCGI_UnknownTypeBody, $_[0]);
}

# FCGI_BeginRequestRecord

sub build_begin_request_record {
    @_ == 3 || throw(q/Usage: build_begin_request_record(request_id, role, flags)/);
    my ($request_id, $role, $flags) = @_;
    return build_record(FCGI_BEGIN_REQUEST, $request_id,
         build_begin_request_body($role, $flags));
}

# FCGI_EndRequestRecord

sub build_end_request_record {
    @_ == 3 || throw(q/Usage: build_end_request_record(request_id, app_status, protocol_status)/);
    my ($request_id, $app_status, $protocol_status) = @_;
    return build_record(FCGI_END_REQUEST, $request_id,
         build_end_request_body($app_status, $protocol_status));
}

# FCGI_UnknownTypeRecord

sub build_unknown_type_record {
    @_ == 1 || throw(q/Usage: build_unknown_type_record(type)/);
    my ($type) = @_;
    return build_record(FCGI_UNKNOWN_TYPE, FCGI_NULL_REQUEST_ID,
        build_unknown_type_body($type));
}

sub build_record {
    @_ == 2 || @_ == 3 || throw(q/Usage: build_record(type, request_id [, content])/);
    my ($type, $request_id) = @_;

    my $content_length = defined $_[2] ? length $_[2] : 0;
    my $padding_length = (8 - ($content_length % 8)) % 8;

    ($content_length <= FCGI_MAX_CONTENT_LEN)
      || throw(ERRMSG_OCTETS_LE, q/content/, FCGI_MAX_CONTENT_LEN);

    my $res = build_header($type, $request_id, $content_length, $padding_length);

    if ($content_length) {
        $res .= $_[2];
    }

    if ($padding_length) {
        $res .= "\x00" x $padding_length;
    }

    return $res;
}

sub parse_record {
    @_ == 1 || throw(q/Usage: parse_record(octets)/);
    my ($type, $request_id, $content_length) = &parse_header;

    (length $_[0] >= FCGI_HEADER_LEN + $content_length)
      || throw(ERRMSG_OCTETS, q/FCGI_Record/);

    return wantarray 
      ? ($type, $request_id, substr($_[0], FCGI_HEADER_LEN, $content_length))
      : parse_record_body($type, $request_id,
          substr($_[0], FCGI_HEADER_LEN, $content_length));
}

sub parse_record_body {
    @_ == 3 || throw(q/Usage: parse_record_body(type, request_id, content)/);
    my ($type, $request_id) = @_;

    my $content_length = defined $_[2] ? length $_[2] : 0;

    ($content_length <= FCGI_MAX_CONTENT_LEN)
      || throw(ERRMSG_OCTETS_LE, q/content/, FCGI_MAX_CONTENT_LEN);

    my %record = (type => $type, request_id => $request_id);
    if ($type == FCGI_BEGIN_REQUEST) {
        ($request_id != FCGI_NULL_REQUEST_ID && $content_length == 8)
          || throw(ERRMSG_MALFORMED, q/FCGI_BeginRequestRecord/);
        @record{ qw(role flags) } = parse_begin_request_body($_[2]);
    }
    elsif ($type == FCGI_ABORT_REQUEST) {
        ($request_id != FCGI_NULL_REQUEST_ID && $content_length == 0)
          || throw(ERRMSG_MALFORMED, q/FCGI_AbortRequestRecord/);
    }
    elsif ($type == FCGI_END_REQUEST) {
        ($request_id != FCGI_NULL_REQUEST_ID && $content_length == 8)
          || throw(ERRMSG_MALFORMED, q/FCGI_EndRequestRecord/);
        @record{ qw(app_status protocol_status) } 
          = parse_end_request_body($_[2]);
    }
    elsif (   $type == FCGI_PARAMS
           || $type == FCGI_STDIN
           || $type == FCGI_STDOUT
           || $type == FCGI_STDERR
           || $type == FCGI_DATA) {
        ($request_id != FCGI_NULL_REQUEST_ID)
          || throw(ERRMSG_MALFORMED, $FCGI_RECORD_NAME[$type]);
        $record{content} = $content_length ? $_[2] : '';
    }
    elsif (   $type == FCGI_GET_VALUES
           || $type == FCGI_GET_VALUES_RESULT) {
        ($request_id == FCGI_NULL_REQUEST_ID)
          || throw(ERRMSG_MALFORMED, $FCGI_RECORD_NAME[$type]);
        $record{values} = parse_params($_[2]);
    }
    elsif ($type == FCGI_UNKNOWN_TYPE) {
        ($request_id == FCGI_NULL_REQUEST_ID && $content_length == 8)
          || throw(ERRMSG_MALFORMED, q/FCGI_UnknownTypeRecord/);
        $record{unknown_type} = parse_unknown_type_body($_[2]);
    }
    else {
        # unknown record type, pass content so caller can decide appropriate action
        $record{content} = $_[2] if $content_length;
    }

    return \%record;
}

# Reference implementation use 8192 (libfcgi)
sub FCGI_SEGMENT_LEN () { 32768 - FCGI_HEADER_LEN }

sub build_stream {
    @_ == 3 || @_ == 4 || throw(q/Usage: build_stream(type, request_id, content [, terminate])/);
    my ($type, $request_id, undef, $terminate) = @_;

    my $len = defined $_[2] ? length $_[2] : 0;
    my $res = '';

    if ($len) {
        if ($len < FCGI_SEGMENT_LEN) {
            $res = build_record($type, $request_id, $_[2]);
        }
        else {
            my $header = build_header($type, $request_id, FCGI_SEGMENT_LEN, 0);
            my $off    = 0; 
            while ($len >= FCGI_SEGMENT_LEN) {
                $res .= $header;
                $res .= substr($_[2], $off, FCGI_SEGMENT_LEN);
                $len -= FCGI_SEGMENT_LEN;
                $off += FCGI_SEGMENT_LEN;
            }
            if ($len) {
                $res .= build_record($type, $request_id, substr($_[2], $off, $len));
            }
        }
    }

    if ($terminate) {
        $res .= build_header($type, $request_id, 0, 0);
    }

    return $res;
}

sub build_params {
    @_ == 1 || throw(q/Usage: build_params(params)/);
    my ($params) = @_;
    my $res = '';
    while (my ($key, $val) = each(%$params)) {
        for ($key, $val) {
            my $len = defined $_ ? length : 0;
            $res .= $len < 0x80 ? pack('C', $len) : pack('N', $len | 0x8000_0000);
        }
        $res .= $key;
        $res .= $val if defined $val;
    }
    return $res;
}

sub parse_params {
    @_ == 1 || throw(q/Usage: parse_params(octets)/);
    my ($octets) = @_;

    (defined $octets)
      || return +{};

    my ($params, $klen, $vlen) = ({}, 0, 0);
    while (length $octets) {
        for ($klen, $vlen) {
            (1 <= length $octets)
              || throw(ERRMSG_OCTETS, q/FCGI_NameValuePair/);
            $_ = vec(substr($octets, 0, 1, ''), 0, 8);
            next if $_ < 0x80;
            (3 <= length $octets)
              || throw(ERRMSG_OCTETS, q/FCGI_NameValuePair/);
            $_ = vec(pack('C', $_ & 0x7F) . substr($octets, 0, 3, ''), 0, 32);
        }
        ($klen + $vlen <= length $octets)
          || throw(ERRMSG_OCTETS, q/FCGI_NameValuePair/);
        my $key = substr($octets, 0, $klen, '');
        $params->{$key} = substr($octets, 0, $vlen, '');
    }
    return $params;
}

sub check_params {
    @_ == 1 || throw(q/Usage: check_params(octets)/);
    (defined $_[0])
      || return FALSE;

    my ($len, $off, $klen, $vlen) = (length $_[0], 0, 0, 0);
    while ($off < $len) {
        for ($klen, $vlen) {
            (($off += 1) <= $len)
              || return FALSE;
            $_ = vec($_[0], $off - 1, 8);
            next if $_ < 0x80;
            (($off += 3) <= $len)
              || return FALSE;
            $_ = vec(substr($_[0], $off - 4, 4), 0, 32) & 0x7FFF_FFFF;
        }
        (($off += $klen + $vlen) <= $len)
          || return FALSE;
    }
    return TRUE;
}

sub build_begin_request {
    (@_ >= 4 && @_ <= 6) || throw(q/Usage: build_begin_request(request_id, role, flags, params [, stdin [, data]])/);
    my ($request_id, $role, $flags, $params) = @_;

    my $r = build_begin_request_record($request_id, $role, $flags)
          . build_stream(FCGI_PARAMS, $request_id, build_params($params), TRUE);

    if (@_ > 4) {
        $r .= build_stream(FCGI_STDIN, $request_id, $_[4], TRUE);
        if (@_ > 5) {
            $r .= build_stream(FCGI_DATA, $request_id, $_[5], TRUE);
        }
    }
    return $r;
}

sub build_end_request {
    (@_ >= 3 && @_ <= 5) || throw(q/Usage: build_end_request(request_id, app_status, protocol_status [, stdout [, stderr]])/);
    my ($request_id, $app_status, $protocol_status) = @_;

    my $r;
    if (@_ > 3) {
        $r .= build_stream(FCGI_STDOUT, $request_id, $_[3], TRUE);
        if (@_ > 4) {
            $r .= build_stream(FCGI_STDERR, $request_id, $_[4], TRUE);
        }
    }
    $r .= build_end_request_record($request_id, $app_status, $protocol_status);
    return $r;
}

sub get_record_length {
    @_ == 1 || throw(q/Usage: get_record_length(octets)/);
    (defined $_[0] && length $_[0] >= FCGI_HEADER_LEN)
      || return 0;
    return FCGI_HEADER_LEN + vec($_[0], 2, 16)  # contentLength
                           + vec($_[0], 6,  8); # paddingLength
}

sub is_known_type {
    @_ == 1 || throw(q/Usage: is_known_type(type)/);
    my ($type) = @_;
    return ($type > 0 && $type <= FCGI_MAXTYPE);
}

sub is_discrete_type {
    @_ == 1 || throw(q/Usage: is_discrete_type(type)/);
    my ($type) = @_;
    return (   $type == FCGI_BEGIN_REQUEST
            || $type == FCGI_ABORT_REQUEST
            || $type == FCGI_END_REQUEST
            || $type == FCGI_GET_VALUES
            || $type == FCGI_GET_VALUES_RESULT
            || $type == FCGI_UNKNOWN_TYPE );
}

sub is_management_type {
    @_ == 1 || throw(q/Usage: is_management_type(type)/);
    my ($type) = @_;
    return (   $type == FCGI_GET_VALUES
            || $type == FCGI_GET_VALUES_RESULT
            || $type == FCGI_UNKNOWN_TYPE );
}

sub is_stream_type {
    @_ == 1 || throw(q/Usage: is_stream_type(type)/);
    my ($type) = @_;
    return (   $type == FCGI_PARAMS
            || $type == FCGI_STDIN
            || $type == FCGI_STDOUT
            || $type == FCGI_STDERR
            || $type == FCGI_DATA );
}

sub get_type_name {
    @_ == 1 || throw(q/Usage: get_type_name(type)/);
    my ($type) = @_;
    return $FCGI_TYPE_NAME[$type] || sprintf('0x%.2X', $type);
}

sub get_role_name {
    @_ == 1 || throw(q/Usage: get_role_name(role)/);
    my ($role) = @_;
    return $FCGI_ROLE_NAME[$role] || sprintf('0x%.4X', $role);
}

sub get_protocol_status_name {
    @_ == 1 || throw(q/Usage: get_protocol_status_name(protocol_status)/);
    my ($status) = @_;
    return $FCGI_PROTOCOL_STATUS_NAME[$status] || sprintf('0x%.2X', $status);
}

1;

