##
# TrueClass ISO Test

assert('TrueClass', '15.2.5') do
  assert_equal Class, TrueClass.class
end

assert('TrueClass true', '15.2.5.1') do
  assert_true true
  assert_equal TrueClass, true.class
  assert_false TrueClass.method_defined? :new
end

assert('TrueClass#&', '15.2.5.3.1') do
  assert_true true.&(true)
  assert_false true.&(false)
end

assert('TrueClass#^', '15.2.5.3.2') do
  assert_false true.^(true)
  assert_true true.^(false)
end

assert('TrueClass#to_s', '15.2.5.3.3') do
  assert_equal 'true', true.to_s
end

assert('TrueClass#|', '15.2.5.3.4') do
  assert_true true.|(true)
  assert_true true.|(false)
end
