##
# ArgumentError ISO Test

def assert_argnum_error(given, expected, &block)
  assert("wrong number of arguments") do
    message = "wrong number of arguments (given #{given}, expected #{expected})"
    assert_raise_with_message(ArgumentError, message, &block)
  end
end

assert('ArgumentError', '15.2.24') do
  e2 = nil
  a = []
  begin
    # this will cause an exception due to the wrong arguments
    a[]
  rescue => e1
    e2 = e1
  end

  assert_equal(Class, ArgumentError.class)
  assert_equal(ArgumentError, e2.class)
end

assert("'wrong number of arguments' from mrb_get_args") do
  assert_argnum_error(0, "1+"){__send__}
  assert_argnum_error(0, 1..2){Object.const_defined?}
  assert_argnum_error(3, 1..2){Object.const_defined?(:A, true, 2)}
  assert_argnum_error(2, 0..1){{}.default(1, 2)}
  assert_argnum_error(1, 2){Object.const_set(:B)}
  assert_argnum_error(3, 2){Object.const_set(:C, 1, 2)}
end

assert('Call to MRB_ARGS_NONE method') do
  assert_raise(ArgumentError) { nil.__id__ 1 }
  assert_raise(ArgumentError) { nil.__id__ opts: 1 }
end
