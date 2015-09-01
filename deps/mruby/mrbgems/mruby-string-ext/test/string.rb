##
# String(Ext) Test

assert('String#getbyte') do
  str1 = "hello"
  bytes1 = [104, 101, 108, 108, 111]
  assert_equal bytes1[0], str1.getbyte(0)
  assert_equal bytes1[-1], str1.getbyte(-1)
  assert_equal bytes1[6], str1.getbyte(6)

  str2 = "\xFF"
  bytes2 = [0xFF]
  assert_equal bytes2[0], str2.getbyte(0)
end

assert('String#setbyte') do
  str1 = "hello"
  h = "H".getbyte(0)
  str1.setbyte(0, h)
  assert_equal(h, str1.getbyte(0))
  assert_equal("Hello", str1)
end

assert('String#byteslice') do
  str1 = "hello"
  assert_equal("e", str1.byteslice(1))
  assert_equal("o", str1.byteslice(-1))
  assert_equal("ell", str1.byteslice(1..3))
  assert_equal("el", str1.byteslice(1...3))
end

assert('String#dump') do
  ("\1" * 100).dump     # should not raise an exception - regress #1210
  "\0".inspect == "\"\\000\"" and
  "foo".dump == "\"foo\""
end

assert('String#strip') do
  s = "  abc  "
  "".strip == "" and " \t\r\n\f\v".strip == "" and
  "\0a\0".strip == "\0a" and
  "abc".strip     == "abc" and
  "  abc".strip   == "abc" and
  "abc  ".strip   == "abc" and
  "  abc  ".strip == "abc" and
  s == "  abc  "
end

assert('String#lstrip') do
  s = "  abc  "
  s.lstrip
  "".lstrip == "" and " \t\r\n\f\v".lstrip == "" and
  "\0a\0".lstrip == "\0a\0" and
  "abc".lstrip     == "abc"   and
  "  abc".lstrip   == "abc"   and
  "abc  ".lstrip   == "abc  " and
  "  abc  ".lstrip == "abc  " and
  s == "  abc  "
end

assert('String#rstrip') do
  s = "  abc  "
  s.rstrip
  "".rstrip == "" and " \t\r\n\f\v".rstrip == "" and
  "\0a\0".rstrip == "\0a" and
  "abc".rstrip     == "abc"   and
  "  abc".rstrip   == "  abc" and
  "abc  ".rstrip   == "abc"   and
  "  abc  ".rstrip == "  abc" and
  s == "  abc  "
end

assert('String#strip!') do
  s = "  abc  "
  t = "abc"
  s.strip! == "abc" and s == "abc" and t.strip! == nil
end

assert('String#lstrip!') do
  s = "  abc  "
  t = "abc  "
  s.lstrip! == "abc  " and s == "abc  " and t.lstrip! == nil
end

assert('String#rstrip!') do
  s = "  abc  "
  t = "  abc"
  s.rstrip! == "  abc" and s == "  abc" and t.rstrip! == nil
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
  s = "Hello "
  s.concat "World!"
  t = "Hello "
  t << "World!"
  assert_equal "Hello World!", t
  assert_equal "Hello World!", s
end

assert('String#casecmp') do
  assert_equal 1, "abcdef".casecmp("abcde")
  assert_equal 0, "aBcDeF".casecmp("abcdef")
  assert_equal(-1, "abcdef".casecmp("abcdefg"))
  assert_equal 0, "abcdef".casecmp("ABCDEF")
  o = Object.new
  def o.to_str
    "ABCDEF"
  end
  assert_equal 0, "abcdef".casecmp(o)
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

assert('String#chr') do
  assert_equal "a", "abcde".chr
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
  a = "あa"; a.succ!
  assert_equal "あb", a
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
end

assert('String#prepend') do
  a = "world"
  assert_equal "hello world", a.prepend("hello ")
  assert_equal "hello world", a
end

assert('String#ljust') do
  assert_equal "hello", "hello".ljust(4)
  assert_equal "hello               ", "hello".ljust(20)
  assert_equal "hello123412341234123", "hello".ljust(20, '1234')
  assert_equal "hello", "hello".ljust(-3)
end

assert('String#upto') do
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
end
