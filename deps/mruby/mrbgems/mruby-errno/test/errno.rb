assert('Errno') do
  assert_equal(Module, Errno.class)
end

assert('SystemCallError') do
  assert_equal(Class, SystemCallError.class)
end

assert('SystemCallError superclass') do
  assert_equal(StandardError, SystemCallError.superclass)
end

assert('SystemCallError#initialize') do
  assert_equal("unknown error - a", SystemCallError.new("a").message)
  assert_equal("Unknown error: 12345 - a", SystemCallError.new("a", 12345).message)
  assert_equal("Unknown error: 12345", SystemCallError.new(12345).message)
end

assert('SystemCallError#errno') do
  assert_equal 1, SystemCallError.new("a", 1).errno
  assert_equal 1, SystemCallError.new(1).errno
  assert_equal 12345, SystemCallError.new("a", 12345).errno
  assert_equal 23456, SystemCallError.new(23456).errno
end

assert('SystemCallError#inspect') do
  assert_equal("unknown error - a (SystemCallError)", SystemCallError.new("a").inspect)
end

assert('Errno::NOERROR') do
  assert_equal(Class, Errno::NOERROR.class)
end

# Is there any platform does not have EPERM?
assert('Errno::EPERM') do
  assert_equal(Class, Errno::EPERM.class)
end

assert('Errno::EPERM superclass') do
  assert_equal(SystemCallError, Errno::EPERM.superclass)
end

assert('Errno::EPERM::Errno') do
  assert_true(Errno::EPERM::Errno.is_a?(Fixnum))
end

assert('Errno::EPERM#message') do
  msg = Errno::EPERM.new.message
  assert_equal("#{msg} - a", Errno::EPERM.new("a").message)
end

assert('Errno::EPERM#inspect') do
  msg = Errno::EPERM.new.message
  assert_equal("#{msg} (Errno::EPERM)", Errno::EPERM.new.inspect)

  msg = Errno::EPERM.new.message
  assert_equal("#{msg} - a (Errno::EPERM)", Errno::EPERM.new("a").inspect)
end
