##
# Numeric(Ext) Test

assert('Integer#div') do
  assert_equal 52, 365.div(7)
end

assert('Float#div') do
  skip unless Object.const_defined?(:Float)
  assert_float 52, 365.2425.div(7)
end

assert('Integer#zero?') do
  assert_equal true, 0.zero?
  assert_equal false, 1.zero?
end

assert('Integer#nonzero?') do
  assert_equal nil, 0.nonzero?
  assert_equal 1000, 1000.nonzero?
end
