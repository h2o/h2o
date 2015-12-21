##
# Numeric(Ext) Test

assert('Integer#chr') do
  assert_equal("A", 65.chr)
  assert_equal("B", 0x42.chr)

  # multibyte encoding (not support yet)
  assert_raise(RangeError) { 256.chr }
end

assert('Integer#div') do
  assert_equal 52, 365.div(7)
end

assert('Float#div') do
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
