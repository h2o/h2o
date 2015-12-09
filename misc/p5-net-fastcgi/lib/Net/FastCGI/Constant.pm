package Net::FastCGI::Constant;

use strict;
use warnings;

BEGIN {
    our $VERSION        = '0.14';
    my @common          = qw[ FCGI_MAX_CONTENT_LEN
                              FCGI_MAX_LEN
                              FCGI_HEADER_LEN
                              FCGI_VERSION_1
                              FCGI_NULL_REQUEST_ID ];

    my @type            = qw[ FCGI_BEGIN_REQUEST
                              FCGI_ABORT_REQUEST
                              FCGI_END_REQUEST
                              FCGI_PARAMS
                              FCGI_STDIN
                              FCGI_STDOUT
                              FCGI_STDERR
                              FCGI_DATA
                              FCGI_GET_VALUES
                              FCGI_GET_VALUES_RESULT
                              FCGI_UNKNOWN_TYPE
                              FCGI_MAXTYPE ];

    my @role            = qw[ FCGI_RESPONDER
                              FCGI_AUTHORIZER
                              FCGI_FILTER ];

    my @flag            = qw[ FCGI_KEEP_CONN ];

    my @protocol_status = qw[ FCGI_REQUEST_COMPLETE
                              FCGI_CANT_MPX_CONN
                              FCGI_OVERLOADED
                              FCGI_UNKNOWN_ROLE ];

    my @value           = qw[ FCGI_MAX_CONNS
                              FCGI_MAX_REQS
                              FCGI_MPXS_CONNS ];

    my @pack            = qw[ FCGI_Header
                              FCGI_BeginRequestBody
                              FCGI_EndRequestBody
                              FCGI_UnknownTypeBody ];

    my @name            = qw[ @FCGI_TYPE_NAME
                              @FCGI_RECORD_NAME
                              @FCGI_ROLE_NAME
                              @FCGI_PROTOCOL_STATUS_NAME ];

    our @EXPORT_OK      = (  @common,
                             @type,
                             @role,
                             @flag,
                             @protocol_status,
                             @value,
                             @pack,
                             @name );

    our %EXPORT_TAGS    = (  all             => \@EXPORT_OK,
                             common          => \@common,
                             type            => \@type,
                             role            => \@role,
                             flag            => \@flag,
                             protocol_status => \@protocol_status,
                             value           => \@value,
                             pack            => \@pack );

    our @FCGI_TYPE_NAME = (
        undef,                        #  0
        'FCGI_BEGIN_REQUEST',         #  1
        'FCGI_ABORT_REQUEST',         #  2
        'FCGI_END_REQUEST',           #  3
        'FCGI_PARAMS',                #  4
        'FCGI_STDIN',                 #  5
        'FCGI_STDOUT',                #  6
        'FCGI_STDERR',                #  7
        'FCGI_DATA',                  #  8
        'FCGI_GET_VALUES',            #  9
        'FCGI_GET_VALUES_RESULT',     # 10
        'FCGI_UNKNOWN_TYPE'           # 11
    );

    our @FCGI_RECORD_NAME = (
        undef,                        #  0
        'FCGI_BeginRequestRecord',    #  1
        'FCGI_AbortRequestRecord',    #  2
        'FCGI_EndRequestRecord',      #  3
        'FCGI_ParamsRecord',          #  4
        'FCGI_StdinRecord',           #  5
        'FCGI_StdoutRecord',          #  6
        'FCGI_StderrRecord',          #  7
        'FCGI_DataRecord',            #  8
        'FCGI_GetValuesRecord',       #  9
        'FCGI_GetValuesResultRecord', # 10
        'FCGI_UnknownTypeRecord',     # 11
    );

    our @FCGI_ROLE_NAME = (
        undef,                        #  0
        'FCGI_RESPONDER',             #  1
        'FCGI_AUTHORIZER',            #  2
        'FCGI_FILTER',                #  3
    );

    our @FCGI_PROTOCOL_STATUS_NAME = (
        'FCGI_REQUEST_COMPLETE',      #  0
        'FCGI_CANT_MPX_CONN',         #  1
        'FCGI_OVERLOADED',            #  2
        'FCGI_UNKNOWN_ROLE',          #  3
    );

    if (Internals->can('SvREADONLY')) { # 5.8
        Internals::SvREADONLY(@FCGI_TYPE_NAME, 1);
        Internals::SvREADONLY(@FCGI_RECORD_NAME, 1);
        Internals::SvREADONLY(@FCGI_ROLE_NAME, 1);
        Internals::SvREADONLY(@FCGI_PROTOCOL_STATUS_NAME, 1);
        Internals::SvREADONLY($_, 1) for @FCGI_TYPE_NAME,
                                         @FCGI_RECORD_NAME,
                                         @FCGI_ROLE_NAME,
                                         @FCGI_PROTOCOL_STATUS_NAME;
    }

    require Exporter;
    *import = \&Exporter::import;
}


sub FCGI_LISTENSOCK_FILENO   () {      0 }

# common
sub FCGI_MAX_CONTENT_LEN     () { 0xFFFF }
sub FCGI_MAX_LEN             () { 0xFFFF } # deprecated
sub FCGI_HEADER_LEN          () {      8 }
sub FCGI_VERSION_1           () {      1 }
sub FCGI_NULL_REQUEST_ID     () {      0 }

# type
sub FCGI_BEGIN_REQUEST       () {      1 }
sub FCGI_ABORT_REQUEST       () {      2 }
sub FCGI_END_REQUEST         () {      3 }
sub FCGI_PARAMS              () {      4 }
sub FCGI_STDIN               () {      5 }
sub FCGI_STDOUT              () {      6 }
sub FCGI_STDERR              () {      7 }
sub FCGI_DATA                () {      8 }
sub FCGI_GET_VALUES          () {      9 }
sub FCGI_GET_VALUES_RESULT   () {     10 }
sub FCGI_UNKNOWN_TYPE        () {     11 }
sub FCGI_MAXTYPE             () { FCGI_UNKNOWN_TYPE }

# role
sub FCGI_RESPONDER           () {      1 }
sub FCGI_AUTHORIZER          () {      2 }
sub FCGI_FILTER              () {      3 }

# flags
sub FCGI_KEEP_CONN           () {      1 }

# protocol status
sub FCGI_REQUEST_COMPLETE    () {      0 }
sub FCGI_CANT_MPX_CONN       () {      1 }
sub FCGI_OVERLOADED          () {      2 }
sub FCGI_UNKNOWN_ROLE        () {      3 }

# value
sub FCGI_MAX_CONNS           () { 'FCGI_MAX_CONNS'  }
sub FCGI_MAX_REQS            () { 'FCGI_MAX_REQS'   }
sub FCGI_MPXS_CONNS          () { 'FCGI_MPXS_CONNS' }

# pack
sub FCGI_Header              () { 'CCnnCx' }
sub FCGI_BeginRequestBody    () { 'nCx5'   }
sub FCGI_EndRequestBody      () { 'NCx3'   }
sub FCGI_UnknownTypeBody     () { 'Cx7'    }

1;

