use strict;
use warnings;

$main::push_expr = sub {
    my $src = shift;
    return qq{{ h2o_iovec_t _s = ($src); if (_s.len != 0 && _s.base[_s.len - 1] == '\\n') --_s.len; h2o_buffer_reserve(&_, _s.len); memcpy(_->bytes + _->size, _s.base, _s.len); _->size += _s.len; }};
};

$main::push_void_expr = sub {
    my $src = shift;
    return qq{{ size_t _l = _->size; { $src }; if (_->size != 0 && _l != _->size && _->bytes[_->size - 1] == '\\n') --_->size; }};
};

$main::push_str = sub {
    my $str = shift;
    $str =~ s/([\\'"])/\\$1/gs;
    $str =~ s/\n/\\n/gs;
    return $main::push_expr->(qq{h2o_iovec_init(H2O_STRLIT("$str"))});
};

1;
