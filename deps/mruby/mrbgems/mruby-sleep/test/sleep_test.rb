assert("sleep works") do
  assert_nothing_raised { sleep(1) }
  assert_nothing_raised { sleep(0) }
end

assert("sleep would accept non-negative float value") do
  skip unless Object.const_defined?(:Float)
  assert_nothing_raised { sleep(0.01) }
  assert_nothing_raised { sleep(0.0) }
  assert_nothing_raised { sleep(-0.0) }
end

assert("sleep would not accept negative integer value") do
  assert_raise(ArgumentError) { sleep(-1) }
end

assert("sleep would not accept negative float value") do
  skip unless Object.const_defined?(:Float)
  assert_raise(ArgumentError) { sleep(-0.1) }
end

assert("usleep works") do
  assert_nothing_raised { usleep(100) }
  assert_nothing_raised { usleep(0) }
end

assert("usleep would not accept negative value") do
  assert_raise(ArgumentError) { usleep(-100) }
end
