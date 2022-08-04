# coding: utf-8
##
# String(Ext) Test

UTF8STRING = __ENCODING__ == "UTF-8"

def assert_upto(exp, receiver, *args)
  act = []
  receiver.upto(*args) { |v| act << v }
  assert_equal exp, act
end

assert('String#dump') do
  assert_equal("\"\\x00\"", "\0".dump)
  assert_equal("\"foo\"", "foo".dump)
  assert_equal('"\xe3\x82\x8b"', "る".dump)
  assert_nothing_raised { ("\1" * 100).dump }   # regress #1210
end

assert('String#strip') do
  s = "  abc  "
  assert_equal("abc", s.strip)
  assert_equal("  abc  ", s)
  assert_equal("", "".strip)
  assert_equal("", " \t\r\n\f\v".strip)
  assert_equal("\0a", "\0a\0".strip)
  assert_equal("abc", "abc".strip)
  assert_equal("abc", "  abc".strip)
  assert_equal("abc", "abc  ".strip)
end

assert('String#lstrip') do
  s = "  abc  "
  assert_equal("abc  ", s.lstrip)
  assert_equal("  abc  ", s)
  assert_equal("", "".lstrip)
  assert_equal("", " \t\r\n\f\v".lstrip)
  assert_equal("\0a\0", "\0a\0".lstrip)
  assert_equal("abc", "abc".lstrip)
  assert_equal("abc", "  abc".lstrip)
  assert_equal("abc  ", "abc  ".lstrip)
end

assert('String#rstrip') do
  s = "  abc  "
  assert_equal("  abc", s.rstrip)
  assert_equal("  abc  ", s)
  assert_equal("", "".rstrip)
  assert_equal("", " \t\r\n\f\v".rstrip)
  assert_equal("\0a", "\0a\0".rstrip)
  assert_equal("abc", "abc".rstrip)
  assert_equal("  abc", "  abc".rstrip)
  assert_equal("abc", "abc  ".rstrip)
end

assert('String#strip!') do
  s = "  abc  "
  t = "abc"
  assert_equal("abc", s.strip!)
  assert_equal("abc", s)
  assert_nil(t.strip!)
  assert_equal("abc", t)
end

assert('String#lstrip!') do
  s = "  abc  "
  t = "abc  "
  assert_equal("abc  ", s.lstrip!)
  assert_equal("abc  ", s)
  assert_nil(t.lstrip!)
  assert_equal("abc  ", t)
end

assert('String#rstrip!') do
  s = "  abc  "
  t = "  abc"
  assert_equal("  abc", s.rstrip!)
  assert_equal("  abc", s)
  assert_nil(t.rstrip!)
  assert_equal("  abc", t)
end

assert('String#swapcase') do
  assert_equal "hELLO", "Hello".swapcase
  assert_equal "CyBeR_pUnK11", "cYbEr_PuNk11".swapcase
end

assert('String#swapcase!') do
  s = "Hello"
  t = s.clone
  t.swapcase!
  assert_equal s.swapcase, t
end

assert('String#concat') do
  assert_equal "Hello World!", "Hello " << "World" << 33
  assert_equal "Hello World!", "Hello ".concat("World").concat(33)
  assert_raise(TypeError) { "".concat(Object.new) }

  if UTF8STRING
    assert_equal "H«", "H" << 0xab
    assert_equal "Hは", "H" << 12399
  else
    assert_equal "H\xab", "H" << 0xab
    assert_raise(RangeError) { "H" << 12399 }
  end
end

assert('String#casecmp') do
  assert_equal 1, "abcdef".casecmp("abcde")
  assert_equal 0, "aBcDeF".casecmp("abcdef")
  assert_equal(-1, "abcdef".casecmp("abcdefg"))
  assert_equal 0, "abcdef".casecmp("ABCDEF")
end

assert('String#count') do
  s = "abccdeff123"
  assert_equal 0, s.count("")
  assert_equal 1, s.count("a")
  assert_equal 2, s.count("ab")
  assert_equal 9, s.count("^c")
  assert_equal 8, s.count("a-z")
  assert_equal 4, s.count("a0-9")
end

assert('String#tr') do
  assert_equal "ABC", "abc".tr('a-z', 'A-Z')
  assert_equal "hippo", "hello".tr('el', 'ip')
  assert_equal "Ruby", "Lisp".tr("Lisp", "Ruby")
  assert_equal "*e**o", "hello".tr('^aeiou', '*')
  assert_equal "heo", "hello".tr('l', '')
end

assert('String#tr!') do
  s = "abcdefghijklmnopqR"
  assert_equal "ab12222hijklmnopqR", s.tr!("cdefg", "12")
  assert_equal "ab12222hijklmnopqR", s
end

assert('String#tr_s') do
  assert_equal "hero", "hello".tr_s('l', 'r')
  assert_equal "h*o", "hello".tr_s('el', '*')
  assert_equal "hhxo", "hello".tr_s('el', 'hx')
end

assert('String#tr_s!') do
  s = "hello"
  assert_equal "hero", s.tr_s!('l', 'r')
  assert_equal "hero", s
  assert_nil s.tr_s!('l', 'r')
end

assert('String#squeeze') do
  assert_equal "yelow mon", "yellow moon".squeeze
  assert_equal " now is the", "  now   is  the".squeeze(" ")
  assert_equal "puters shot balls", "putters shoot balls".squeeze("m-z")
end

assert('String#squeeze!') do
  s = "  now   is  the"
  assert_equal " now is the", s.squeeze!(" ")
  assert_equal " now is the", s
end

assert('String#delete') do
  assert_equal "he", "hello".delete("lo")
  assert_equal "hll", "hello".delete("aeiou")
  assert_equal "ll", "hello".delete("^l")
  assert_equal "ho", "hello".delete("ej-m")
end

assert('String#delete!') do
  s = "hello"
  assert_equal "he", s.delete!("lo")
  assert_equal "he", s
  assert_nil s.delete!("lz")
end

assert('String#start_with?') do
  assert_true "hello".start_with?("heaven", "hell")
  assert_true !"hello".start_with?("heaven", "paradise")
  assert_true !"h".start_with?("heaven", "hell")
  assert_raise TypeError do "hello".start_with?(true) end
end

assert('String#end_with?') do
  assert_true "string".end_with?("ing", "mng")
  assert_true !"string".end_with?("str", "tri")
  assert_true !"ng".end_with?("ing", "mng")
  assert_raise TypeError do "hello".end_with?(true) end
end

assert('String#partition') do
  assert_equal ["a", "x", "axa"], "axaxa".partition("x")
  assert_equal ["aaaaa", "", ""], "aaaaa".partition("x")
  assert_equal ["", "", "aaaaa"], "aaaaa".partition("")
  assert_equal ["", "a", "aaaa"], "aaaaa".partition("a")
  assert_equal ["aaaa", "b", ""], "aaaab".partition("b")
  assert_equal ["", "b", "aaaa"], "baaaa".partition("b")
  assert_equal ["", "", ""],      "".partition("a")
end

assert('String#rpartition') do
  assert_equal ["axa", "x", "a"], "axaxa".rpartition("x")
  assert_equal ["", "", "aaaaa"], "aaaaa".rpartition("x")
  assert_equal ["aaaaa", "", ""], "aaaaa".rpartition("")
  assert_equal ["aaaa", "a", ""], "aaaaa".rpartition("a")
  assert_equal ["aaaa", "b", ""], "aaaab".rpartition("b")
  assert_equal ["", "b", "aaaa"], "baaaa".rpartition("b")
  assert_equal ["", "", ""],      "".rpartition("a")
end

assert('String#hex') do
  assert_equal 16, "10".hex
  assert_equal 255, "ff".hex
  assert_equal 16, "0x10".hex
  assert_equal (-16), "-0x10".hex
  assert_equal 0, "xyz".hex
  assert_equal 16, "10z".hex
  assert_equal 16, "1_0".hex
  assert_equal 0, "".hex
end

assert('String#oct') do
  assert_equal 8, "10".oct
  assert_equal 7, "7".oct
  assert_equal 0, "8".oct
  assert_equal 0, "9".oct
  assert_equal 0, "xyz".oct
  assert_equal 8, "10z".oct
  assert_equal 8, "1_0".oct
  assert_equal 8, "010".oct
  assert_equal (-8), "-10".oct
end

assert('String#lines') do
  assert_equal ["Hel\n", "lo\n", "World!"], "Hel\nlo\nWorld!".lines
  assert_equal ["Hel\n", "lo\n", "World!\n"], "Hel\nlo\nWorld!\n".lines
  assert_equal ["\n", "\n", "\n"], "\n\n\n".lines
  assert_equal [], "".lines
end

assert('String#clear') do
  # embed string
  s = "foo"
  assert_equal("", s.clear)
  assert_equal("", s)

  # not embed string and not shared string
  s = "foo" * 100
  a = s
  assert_equal("", s.clear)
  assert_equal("", s)
  assert_equal("", a)

  # shared string
  s = "foo" * 100
  a = s[10, 90]                # create shared string
  assert_equal("", s.clear)    # clear
  assert_equal("", s)          # s is cleared
  assert_not_equal("", a)      # a should not be affected
end

assert('String#slice!') do
  a = "AooBar"
  b = a.dup
  assert_equal "A", a.slice!(0)
  assert_equal "AooBar", b

  a = "FooBar"
  assert_equal "r", a.slice!(-1)
  assert_equal "FooBa", a

  a = "FooBar"
  assert_nil a.slice!(6)
  assert_nil a.slice!(-7)
  assert_equal "FooBar", a

  a = "FooBar"
  assert_equal "Foo", a.slice!(0, 3)
  assert_equal "Bar", a

  a = "FooBar"
  assert_equal "Bar", a.slice!(-3, 3)
  assert_equal "Foo", a

  a = "FooBar"
  assert_equal "", a.slice!(6, 2)
  assert_equal "FooBar", a

  a = "FooBar"
  assert_nil a.slice!(-7,10)
  assert_equal "FooBar", a

  a = "FooBar"
  assert_equal "Foo", a.slice!(0..2)
  assert_equal "Bar", a

  a = "FooBar"
  assert_equal "Bar", a.slice!(-3..-1)
  assert_equal "Foo", a

  a = "FooBar"
  assert_equal "", a.slice!(6..2)
  assert_equal "FooBar", a

  a = "FooBar"
  assert_nil a.slice!(-10..-7)
  assert_equal "FooBar", a

  a = "FooBar"
  assert_equal "Foo", a.slice!("Foo")
  assert_equal "Bar", a

  a = "FooBar"
  assert_nil a.slice!("xyzzy")
  assert_equal "FooBar", a

  assert_raise(ArgumentError) { "foo".slice! }
end

assert('String#succ') do
  assert_equal "", "".succ
  assert_equal "1", "0".succ
  assert_equal "10", "9".succ
  assert_equal "01", "00".succ
  assert_equal "a1", "a0".succ
  assert_equal "A1", "A0".succ
  assert_equal "10", "09".succ
  assert_equal "b0", "a9".succ
  assert_equal "B0", "A9".succ

  assert_equal "b", "a".succ
  assert_equal "aa", "z".succ
  assert_equal "ab", "aa".succ
  assert_equal "Ab", "Aa".succ
  assert_equal "0b", "0a".succ
  assert_equal "ba", "az".succ
  assert_equal "Ba", "Az".succ
  assert_equal "1a", "0z".succ

  assert_equal "B", "A".succ
  assert_equal "AA", "Z".succ
  assert_equal "AB", "AA".succ
  assert_equal "aB", "aA".succ
  assert_equal "0B", "0A".succ
  assert_equal "BA", "AZ".succ
  assert_equal "bA", "aZ".succ
  assert_equal "1A", "0Z".succ

  assert_equal ".", "-".succ
  assert_equal "\x01\x00", "\xff".succ
  assert_equal "-b", "-a".succ
  assert_equal "-aa", "-z".succ
  assert_equal "-a-b-", "-a-a-".succ
  assert_equal "-b-", "-a-".succ
  assert_equal "-aa-", "-z-".succ
  assert_equal "あb", "あa".succ
  assert_equal "あba", "あaz".succ

  a = ""; a.succ!
  assert_equal "", a
  a = "0"; a.succ!
  assert_equal "1", a
  a = "9"; a.succ!
  assert_equal "10", a
  a = "00"; a.succ!
  assert_equal "01", a
  a = "a0"; a.succ!
  assert_equal "a1", a
  a = "A0"; a.succ!
  assert_equal "A1", a
  a = "09"; a.succ!
  assert_equal "10", a
  a = "a9"; a.succ!
  assert_equal "b0", a
  a = "A9"; a.succ!
  assert_equal "B0", a

  a = "a"; a.succ!
  assert_equal "b", a
  a = "z"; a.succ!
  assert_equal "aa", a
  a = "aa"; a.succ!
  assert_equal "ab", a
  a = "Aa"; a.succ!
  assert_equal "Ab", a
  a = "0a"; a.succ!
  assert_equal "0b", a
  a = "az"; a.succ!
  assert_equal "ba", a
  a = "Az"; a.succ!
  assert_equal "Ba", a
  a = "0z"; a.succ!
  assert_equal "1a", a

  a = "A"; a.succ!
  assert_equal "B", a
  a = "Z"; a.succ!
  assert_equal "AA", a
  a = "AA"; a.succ!
  assert_equal "AB", a
  a = "aA"; a.succ!
  assert_equal "aB", a
  a = "0A"; a.succ!
  assert_equal "0B", a
  a = "AZ"; a.succ!
  assert_equal "BA", a
  a = "aZ"; a.succ!
  assert_equal "bA", a
  a = "0Z"; a.succ!
  assert_equal "1A", a

  a = "-"; a.succ!
  assert_equal ".", a
  a = "\xff"; a.succ!
  assert_equal "\x01\x00", a
  a = "-a"; a.succ!
  assert_equal "-b", a
  a = "-z"; a.succ!
  assert_equal "-aa", a
  a = "-a-a-"; a.succ!
  assert_equal "-a-b-", a
  a = "-a-"; a.succ!
  assert_equal "-b-", a
  a = "-z-"; a.succ!
  assert_equal "-aa-", a
  a = "あb"; a.succ!
  assert_equal "あc", a
  a = "あaz"; a.succ!
  assert_equal "あba", a
end

assert('String#next') do
  assert_equal "01", "00".next

  a = "00"; a.next!
  assert_equal "01", a
end

assert('String#insert') do
  assert_equal "Xabcd", "abcd".insert(0, 'X')
  assert_equal "abcXd", "abcd".insert(3, 'X')
  assert_equal "abcdX", "abcd".insert(4, 'X')
  assert_equal "abXcd", "abcd".insert(-3, 'X')
  assert_equal "abcdX", "abcd".insert(-1, 'X')
  assert_raise(IndexError) { "abcd".insert(5, 'X') }
  assert_raise(IndexError) { "abcd".insert(-6, 'X') }

  a = "abcd"
  a.insert(0, 'X')
  assert_equal "Xabcd", a
end

assert('String#prepend') do
  a = "world"
  assert_equal "hello world", a.prepend("hello ")
  assert_equal "hello world", a
end

assert('String#ljust') do
  assert_equal "hello", "hello".ljust(4)
  assert_equal "hello               ", "hello".ljust(20)
  assert_equal 20, "hello".ljust(20).length
  assert_equal "hello123412341234123", "hello".ljust(20, '1234')
  assert_equal "hello", "hello".ljust(-3)
end

assert('String#rjust') do
  assert_equal "hello", "hello".rjust(4)
  assert_equal "               hello", "hello".rjust(20)
  assert_equal 20, "hello".rjust(20).length
  assert_equal "123412341234123hello", "hello".rjust(20, '1234')
  assert_equal "hello", "hello".rjust(-3)
end

assert('String#center') do
  assert_equal "hello", "hello".center(4)
  assert_equal "       hello        ", "hello".center(20)
  assert_equal 20, "hello".center(20).length
  assert_equal "1231231hello12312312", "hello".center(20, '123')
  assert_equal "hello", "hello".center(-3)
end

if UTF8STRING
  assert('String#ljust with UTF8') do
    assert_equal "helloん              ", "helloん".ljust(20)
    assert_equal "helloó                            ", "helloó".ljust(34)
    assert_equal 34, "helloó".ljust(34).length
    assert_equal "helloんんんんんんんんんんんんんん", "hello".ljust(19, 'ん')
    assert_equal "helloんんんんんんんんんんんんんんん", "hello".ljust(20, 'ん')
  end

  assert('String#rjust with UTF8') do
    assert_equal "              helloん", "helloん".rjust(20)
    assert_equal "                            helloó", "helloó".rjust(34)
    # assert_equal 34, "helloó".rjust(34).length
    assert_equal "んんんんんんんんんんんんんんhello", "hello".rjust(19, 'ん')
    assert_equal "んんんんんんんんんんんんんんんhello", "hello".rjust(20, 'ん')
  end

  assert('UTF8 byte counting') do
    ret = '                                  '
    ret[-6..-1] = "helloó"
    assert_equal 34, ret.length
  end
end

assert('String#ljust should not change string') do
  a = "hello"
  a.ljust(20)
  assert_equal "hello", a
end

assert('String#rjust should not change string') do
  a = "hello"
  a.rjust(20)
  assert_equal "hello", a
end

assert('String#ljust should raise on zero width padding') do
  assert_raise(ArgumentError) { "foo".ljust(10, '') }
end

assert('String#rjust should raise on zero width padding') do
  assert_raise(ArgumentError) { "foo".rjust(10, '') }
end

assert('String#upto') do
  assert_upto %w(a8 a9 b0 b1 b2 b3 b4 b5 b6), "a8", "b6"
  assert_upto ["9", "10", "11"], "9", "11"
  assert_upto [], "25", "5"
  assert_upto ["07", "08", "09", "10", "11"], "07", "11"
  assert_upto ["9", ":", ";", "<", "=", ">", "?", "@", "A"], "9", "A"

  if UTF8STRING
    assert_upto %w(あ ぃ い ぅ う ぇ え ぉ お), "あ", "お"
  end

  a     = "aa"
  start = "aa"
  count = 0
  assert_equal("aa", a.upto("zz") {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(676, count)

  a     = "a"
  start = "a"
  count = 0
  assert_equal("a", a.upto("a") {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(1, count)

  a     = "a"
  start = "a"
  count = 0
  assert_equal("a", a.upto("b", true) {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(1, count)

  a     = "0"
  start = "0"
  count = 0
  assert_equal("0", a.upto("0") {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(1, count)

  a     = "0"
  start = "0"
  count = 0
  assert_equal("0", a.upto("-1") {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(0, count)

  a     = "-1"
  start = "-1"
  count = 0
  assert_equal("-1", a.upto("-2") {|s|
    assert_equal(start, s)
    start.succ!
    count += 1
  })
  assert_equal(2, count)

  assert_raise(TypeError) { "a".upto(:c) {} }
end

assert('String#ord') do
  got = "hello!".split('').map {|x| x.ord}
  expect = [104, 101, 108, 108, 111, 33]
  unless UTF8STRING
    got << "\xff".ord
    expect << 0xff
  end
  assert_equal expect, got
end

assert('String#ord(UTF-8)') do
  got = "こんにちは世界!".split('').map {|x| x.ord}
  expect = [0x3053,0x3093,0x306b,0x3061,0x306f,0x4e16,0x754c,0x21]
  assert_equal expect, got
end if UTF8STRING

assert('String#chr') do
  assert_equal "a", "abcde".chr
  assert_equal "h", "hello!".chr
  assert_equal "", "".chr
end

assert('String#chr(UTF-8)') do
  assert_equal "こ", "こんにちは世界!".chr
end if UTF8STRING

assert('String#chars') do
  expect = ["h", "e", "l", "l", "o", "!"]
  assert_equal expect, "hello!".chars
  s = ""
  "hello!".chars do |x|
    s += x
  end
  assert_equal "hello!", s
end

assert('String#chars(UTF-8)') do
  expect = ['こ', 'ん', 'に', 'ち', 'は', '世', '界', '!']
  assert_equal expect, "こんにちは世界!".chars
  s = ""
  "こんにちは世界!".chars do |x|
    s += x
  end
  assert_equal "こんにちは世界!", s
end if UTF8STRING

assert('String#each_char') do
  chars = []
  "hello!".each_char do |x|
    chars << x
  end
  assert_equal ["h", "e", "l", "l", "o", "!"], chars
end

assert('String#each_char(UTF-8)') do
  chars = []
  "こんにちは世界!".each_char do |x|
    chars << x
  end
  assert_equal ["こ", "ん", "に", "ち", "は", "世", "界", "!"], chars
end if UTF8STRING

assert('String#codepoints') do
  expect = [104, 101, 108, 108, 111, 33]
  assert_equal expect, "hello!".codepoints
  cp = []
  "hello!".codepoints do |x|
    cp << x
  end
  assert_equal expect, cp
end

assert('String#codepoints(UTF-8)') do
  expect = [12371, 12435, 12395, 12385, 12399, 19990, 30028, 33]
  assert_equal expect, "こんにちは世界!".codepoints
  cp = []
  "こんにちは世界!".codepoints do |x|
    cp << x
  end
  assert_equal expect, cp
end if UTF8STRING

assert('String#each_codepoint') do
  expect = [104, 101, 108, 108, 111, 33]
  cp = []
  "hello!".each_codepoint do |x|
    cp << x
  end
  assert_equal expect, cp
end

assert('String#each_codepoint(UTF-8)') do
  expect = [12371, 12435, 12395, 12385, 12399, 19990, 30028, 33]
  cp = []
  "こんにちは世界!".each_codepoint do |x|
    cp << x
  end
  assert_equal expect, cp
end if UTF8STRING

assert('String#delete_prefix') do
  assert_equal "llo", "hello".delete_prefix("he")
  assert_equal "hello", "hello".delete_prefix("llo")
  assert_equal "llo", "hello".delete_prefix!("he")
  assert_nil "hello".delete_prefix!("llo")
end

assert('String#delete_suffix') do
  assert_equal "he", "hello".delete_suffix("llo")
  assert_equal "hello", "hello".delete_suffix("he")
  assert_equal "he", "hello".delete_suffix!("llo")
  assert_nil "hello".delete_suffix!("he")
end
