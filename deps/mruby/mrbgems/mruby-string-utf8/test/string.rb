# -*- coding: utf-8 -*-
##
# String(utf8) Test

assert('String#[]') do
  assert_equal "ち", "こんにちは世界"[3]
  assert_equal nil, "こんにちは世界"[20]
  assert_equal "世", "こんにちは世界"[-2]
  assert_equal "世界", "こんにちは世界"[-2..-1]
  assert_equal "んに", "こんにちは世界"[1,2]
  assert_equal "世", "こんにちは世界"["世"]
  assert_equal 'b', 'abc'[1.1]
end

assert('String#reverse', '15.2.10.5.29') do
  a = 'こんにちは世界!'
  a.reverse

  assert_equal 'こんにちは世界!', a
  assert_equal '!界世はちにんこ', 'こんにちは世界!'.reverse
end

assert('String#reverse!', '15.2.10.5.30') do
  a = 'こんにちは世界!'
  a.reverse!

  assert_equal '!界世はちにんこ', a
  assert_equal '!界世はちにんこ', 'こんにちは世界!'.reverse!
end

assert('Invalid sequence') do
  assert_equal 5, "\xF8\x88\x80\x80\x80".size
  assert_equal 6, "\xFC\x84\x80\x80\x80\x80".size
end

assert('String#size') do
  str = 'こんにちは世界!'
  assert_equal 8, str.size
  assert_not_equal str.bytesize, str.size
  assert_equal 2, str[1, 2].size
end

assert('String#index') do
  str = "こんにちは世界!\nこんにちは世界!"
  assert_nil str.index('さ')
  assert_equal 3, str.index('ち')
  assert_equal 12, str.index('ち', 10)
  assert_equal nil, str.index("さ")
end

assert('String#ord') do
  got = "こんにちは世界!".split('').map {|x| x.ord}
  expect = [0x3053,0x3093,0x306b,0x3061,0x306f,0x4e16,0x754c,0x21]
  assert_equal expect, got
end

assert('String#split') do
  got = "こんにちは世界!".split('')
  assert_equal ['こ', 'ん', 'に', 'ち', 'は', '世', '界', '!'], got
  got = "こんにちは世界!".split('に')
  assert_equal ['こん', 'ちは世界!'], got
end

assert('String#rindex') do
  str = "こんにちは世界!\nこんにちは世界!"
  assert_nil str.index('さ')
  assert_equal 12, str.rindex('ち')
  assert_equal 3, str.rindex('ち', 10)
end

assert('String#chr(utf-8)') do
  assert_equal "こ", "こんにちは世界!".chr
end

assert('String#chars') do
  expect = ['こ', 'ん', 'に', 'ち', 'は', '世', '界', '!']
  assert_equal expect, "こんにちは世界!".chars
  s = ""
  "こんにちは世界!".chars do |x|
    s += x
  end
  assert_equal "こんにちは世界!", s
end

assert('String#each_char') do
  expect = ['こ', 'ん', 'に', 'ち', 'は', '世', '界', '!']
  s = ""
  "こんにちは世界!".each_char do |x|
    s += x
  end
  assert_equal "こんにちは世界!", s
end
assert('String#codepoints') do
  expect = [12371, 12435, 12395, 12385, 12399, 19990, 30028, 33]
  assert_equal expect, "こんにちは世界!".codepoints
  cp = []
  "こんにちは世界!".codepoints do |x|
    cp << x
  end
  assert_equal expect, cp
end

assert('String#each_codepoint') do
  expect = [12371, 12435, 12395, 12385, 12399, 19990, 30028, 33]
  cp = []
  "こんにちは世界!".each_codepoint do |x|
    cp << x
  end
  assert_equal expect, cp
end
