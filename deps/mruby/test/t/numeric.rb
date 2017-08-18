##
# Numeric ISO Test

assert('Numeric', '15.2.7') do
  assert_equal Class, Numeric.class
end

assert('Numeric#+@', '15.2.7.4.1') do
  assert_equal(+1, +1)
end

assert('Numeric#-@', '15.2.7.4.2') do
  assert_equal(-1, -1)
end

assert('Numeric#abs', '15.2.7.4.3') do
  assert_equal(1, 1.abs)
  assert_equal(1.0, -1.abs)
end

assert('Numeric#pow') do
  assert_equal(8, 2 ** 3)
  assert_equal(-8, -2 ** 3)
  assert_equal(1, 2 ** 0)
  assert_equal(1, 2.2 ** 0)
  assert_equal(0.5, 2 ** -1)
end

assert('Numeric#/', '15.2.8.3.4') do
  n = Class.new(Numeric){ def /(x); 15.1;end }.new

  assert_equal(2, 10/5)
  assert_equal(0.0625, 1/16)
  assert_equal(15.1, n/10)
  assert_raise(TypeError){ 1/n }
  assert_raise(TypeError){ 1/nil }
end

# Not ISO specified

assert('Numeric#**') do
  assert_equal 8.0, 2.0**3
end
