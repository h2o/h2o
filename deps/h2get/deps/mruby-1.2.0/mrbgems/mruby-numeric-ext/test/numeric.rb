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
