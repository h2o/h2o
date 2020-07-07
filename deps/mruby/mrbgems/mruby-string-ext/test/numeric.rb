# coding: utf-8

assert('Integer#chr') do
  assert_equal("A", 65.chr)
  assert_equal("B", 0x42.chr)
  assert_equal("\xab", 171.chr)
  assert_raise(RangeError) { -1.chr }
  assert_raise(RangeError) { 256.chr }

  assert_equal("A", 65.chr("ASCII-8BIT"))
  assert_equal("B", 0x42.chr("BINARY"))
  assert_equal("\xab", 171.chr("ascii-8bit"))
  assert_raise(RangeError) { -1.chr("binary") }
  assert_raise(RangeError) { 256.chr("Ascii-8bit") }
  assert_raise(ArgumentError) { 65.chr("ASCII") }
  assert_raise(ArgumentError) { 65.chr("ASCII-8BIT", 2) }
  assert_raise(TypeError) { 65.chr(:BINARY) }

  if __ENCODING__ == "ASCII-8BIT"
    assert_raise(ArgumentError) { 65.chr("UTF-8") }
  else
    assert_equal("A", 65.chr("UTF-8"))
    assert_equal("B", 0x42.chr("UTF-8"))
    assert_equal("«", 171.chr("utf-8"))
    assert_equal("あ", 12354.chr("Utf-8"))
    assert_raise(RangeError) { -1.chr("utf-8") }
    assert_raise(RangeError) { 0x110000.chr.chr("UTF-8") }
  end
end
