##
# Numeric ISO Test

def assert_step(exp, receiver, args, inf: false)
  act = []
  ret = receiver.step(*args) do |i|
    act << i
    break if inf && exp.size == act.size
  end
  expr = "#{receiver.inspect}.step(#{args.map(&:inspect).join(', ')})"
  assert "assert_step" do
    assert_true(exp.eql?(act), "#{expr}: counters", assertion_diff(exp, act))
    assert_same(receiver, ret, "#{expr}: return value") unless inf
  end
end

assert('Numeric', '15.2.7') do
  assert_equal(Class, Numeric.class)
end

assert('Numeric#+@', '15.2.7.4.1') do
  assert_equal(+1, +1)
end

assert('Numeric#-@', '15.2.7.4.2') do
  assert_equal(-1, -1)
end

assert('Numeric#abs', '15.2.7.4.3') do
  assert_equal(1, 1.abs)
  skip unless Object.const_defined?(:Float)
  assert_equal(1.0, -1.abs)
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
  assert_equal(8, 2 ** 3)
  assert_equal(-8, -2 ** 3)
  assert_equal(1, 2 ** 0)
  skip unless Object.const_defined?(:Float)
  assert_equal(1.0, 2.2 ** 0)
  assert_equal(0.5, 2 ** -1)
  assert_equal(8.0, 2.0**3)
end

assert('Numeric#step') do
  assert_raise(ArgumentError) { 1.step(2, 0) { break } }
  assert_step([2, 3, 4], 2, [4])
  assert_step([10, 8, 6, 4, 2], 10, [1, -2])
  assert_step([], 2, [1, 3])
  assert_step([], -2, [-1, -3])
  assert_step([10, 11, 12, 13], 10, [], inf: true)
  assert_step([10, 7, 4], 10, [nil, -3], inf: true)

  skip unless Object.const_defined?(:Float)
  inf = Float::INFINITY
  assert_raise(ArgumentError) { 1.step(2, 0.0) { break } }
  assert_step([2.0, 3.0, 4.0], 2, [4.0])
  assert_step([7.0, 4.0, 1.0, -2.0], 7, [-4, -3.0])
  assert_step([2.0, 3.0, 4.0], 2.0, [4])
  assert_step([10.0, 11.0, 12.0, 13.0], 10.0, [], inf: true)
  assert_step([10.0, 7.0, 4.0], 10, [nil, -3.0], inf: true)
  assert_step([1.0], 1, [nil, inf])
  assert_step([1.0], 1, [nil, -inf])
  assert_step([1.0], 1, [3, inf])
  assert_step([], 1, [-3, inf])
  assert_step([], 1, [3, -inf])
  assert_step([1.0], 1, [-3, -inf])
  assert_step([1.0], 1, [inf, inf])
  assert_step([], 1, [inf, -inf])
  assert_step([], 1, [-inf, inf])
  assert_step([1.0], 1, [-inf, -inf])
  assert_step([], inf, [2])
  assert_step([], inf, [-2])
  assert_step([], inf, [2, 3])
  assert_step([inf, inf, inf], inf, [2, -3], inf: true)
  assert_step([], inf, [2, inf])
  assert_step([inf], inf, [2, -inf])
  assert_step([], inf, [-2, inf])
  assert_step([inf], inf, [-2, -inf])
  assert_step([], inf, [-2, 3])
  assert_step([inf, inf, inf], inf, [-2, -3], inf: true)
  assert_step([inf], inf, [inf])
  assert_step([], inf, [-inf])
  assert_step([inf], inf, [inf, inf])
  assert_step([inf], inf, [inf, -inf])
  assert_step([inf], inf, [-inf, -inf])
  assert_step([-inf, -inf, -inf], -inf, [2], inf: true)
  assert_step([-inf, -inf, -inf], -inf, [-2], inf: true)
  assert_step([-inf, -inf, -inf], -inf, [2, 3], inf: true)
  assert_step([], -inf, [2, -3])
  assert_step([-inf], -inf, [2, inf])
  assert_step([], -inf, [2, -inf])
  assert_step([-inf], -inf, [-2, inf])
  assert_step([], -inf, [-2, -inf])
  assert_step([-inf, -inf, -inf], -inf, [-2, 3], inf: true)
  assert_step([], -inf, [-2, -3])
  assert_step([-inf, -inf, -inf], -inf, [inf], inf: true)
  assert_step([-inf], -inf, [-inf])
  assert_step([-inf], -inf, [inf, inf])
  assert_step([], -inf, [inf, -inf])
  assert_step([-inf], -inf, [-inf, -inf])
end
