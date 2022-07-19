# Test of the \u notation

assert('bare \u notation test') do
  # Minimum and maximum one byte characters
  assert_equal("\x00", "\u0000")
  assert_equal("\x7F", "\u007F")

  # Minimum and maximum two byte characters
  assert_equal("\xC2\x80", "\u0080")
  assert_equal("\xDF\xBF", "\u07FF")

  # Minimum and maximum three byte characters
  assert_equal("\xE0\xA0\x80", "\u0800")
  assert_equal("\xEF\xBF\xBF", "\uFFFF")

  # Four byte characters require the \U notation
end

assert('braced \u notation test') do
  # Minimum and maximum one byte characters
  assert_equal("\x00", "\u{0000}")
  assert_equal("\x7F", "\u{007F}")

  # Minimum and maximum two byte characters
  assert_equal("\xC2\x80", "\u{0080}")
  assert_equal("\xDF\xBF", "\u{07FF}")

  # Minimum and maximum three byte characters
  assert_equal("\xE0\xA0\x80", "\u{0800}")
  assert_equal("\xEF\xBF\xBF", "\u{FFFF}")

  # Minimum and maximum four byte characters
  assert_equal("\xF0\x90\x80\x80", "\u{10000}")
  assert_equal("\xF4\x8F\xBF\xBF", "\u{10FFFF}")
end

assert('braced multiple \u notation test') do
  assert_equal("ABC", "\u{41 42 43}")
end
