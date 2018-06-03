# coding: utf-8
##
# String ISO Test

UTF8STRING = ("\343\201\202".size == 1)

assert('String', '15.2.10') do
  assert_equal Class, String.class
end

assert('String#<=>', '15.2.10.5.1') do
  a = '' <=> ''
  b = '' <=> 'not empty'
  c = 'not empty' <=> ''
  d = 'abc' <=> 'cba'
  e = 'cba' <=> 'abc'

  assert_equal  0, a
  assert_equal(-1, b)
  assert_equal  1, c
  assert_equal(-1, d)
  assert_equal  1, e
  assert_nil 'a' <=> 1024
end

assert('String#==', '15.2.10.5.2') do
  assert_equal 'abc', 'abc'
  assert_not_equal 'abc', 'cba'
end

# 'String#=~', '15.2.10.5.3' will be tested in mrbgems.

assert('String#+', '15.2.10.5.4') do
  assert_equal 'ab', 'a' + 'b'
end

assert('String#*', '15.2.10.5.5') do
  assert_equal 'aaaaa', 'a' * 5
  assert_equal '', 'a' * 0
  assert_raise(ArgumentError) do
    'a' * -1
  end
end

assert('String#[]', '15.2.10.5.6') do
  # length of args is 1
  a = 'abc'[0]
  b = 'abc'[-1]
  c = 'abc'[10]
  d = 'abc'[-10]
  e = 'abc'[1.1]

  # length of args is 2
  a1 = 'abc'[0, -1]
  b1 = 'abc'[10, 0]
  c1 = 'abc'[-10, 0]
  d1 = 'abc'[0, 0]
  e1 = 'abc'[1, 2]

  # args is RegExp
  # It will be tested in mrbgems.

  # args is String
  a3 = 'abc'['bc']
  b3 = 'abc'['XX']

  assert_equal 'a', 'a'
  # assert_equal 'c', b
  # assert_nil c
  # assert_nil d
  # assert_equal 'b', e
  # assert_nil a1
  # assert_nil b1
  # assert_nil c1
  # assert_equal '', d1
  # assert_equal 'bc', e1
  # assert_equal 'bc', a3
  # assert_nil b3

  # assert_raise(TypeError) do
  #   a[nil]
  # end
end

assert('String#[](UTF-8)', '15.2.10.5.6') do
  assert_equal "ち", "こんにちは世界"[3]
  assert_equal nil, "こんにちは世界"[20]
  assert_equal "世", "こんにちは世界"[-2]
  assert_equal "世界", "こんにちは世界"[-2..-1]
  assert_equal "んに", "こんにちは世界"[1,2]
  assert_equal "世", "こんにちは世界"["世"]
end if UTF8STRING

assert('String#[] with Range') do
  a1 = 'abc'[1..0]
  b1 = 'abc'[1..1]
  c1 = 'abc'[1..2]
  d1 = 'abc'[1..3]
  e1 = 'abc'[1..4]
  f1 = 'abc'[0..-2]
  g1 = 'abc'[-2..3]
  h1 = 'abc'[3..4]
  i1 = 'abc'[4..5]
  j1 = 'abcdefghijklmnopqrstuvwxyz'[1..3]
  a2 = 'abc'[1...0]
  b2 = 'abc'[1...1]
  c2 = 'abc'[1...2]
  d2 = 'abc'[1...3]
  e2 = 'abc'[1...4]
  f2 = 'abc'[0...-2]
  g2 = 'abc'[-2...3]
  h2 = 'abc'[3...4]
  i2 = 'abc'[4...5]
  j2 = 'abcdefghijklmnopqrstuvwxyz'[1...3]

  assert_equal '', a1
  assert_equal 'b', b1
  assert_equal 'bc', c1
  assert_equal 'bc', d1
  assert_equal 'bc', e1
  assert_equal 'ab', f1
  assert_equal 'bc', g1
  assert_equal '', h1
  assert_nil i2
  assert_equal 'bcd', j1
  assert_equal '', a2
  assert_equal '', b2
  assert_equal 'b', c2
  assert_equal 'bc', d2
  assert_equal 'bc', e2
  assert_equal 'a', f2
  assert_equal 'bc', g2
  assert_equal '', h2
  assert_nil i2
  assert_equal 'bc', j2
end

assert('String#[]=') do
  # length of args is 1
  a = 'abc'
  a[0] = 'X'
  assert_equal 'Xbc', a

  b = 'abc'
  b[-1] = 'X'
  assert_equal 'abX', b

  c = 'abc'
  assert_raise(IndexError) do
    c[10] = 'X'
  end

  d = 'abc'
  assert_raise(IndexError) do
    d[-10] = 'X'
  end

  if class_defined?("Float")
   e = 'abc'
   e[1.1] = 'X'
   assert_equal 'aXc', e
  end

  # length of args is 2
  a1 = 'abc'
  assert_raise(IndexError) do
    a1[0, -1] = 'X'
  end

  b1 = 'abc'
  assert_raise(IndexError) do
    b1[10, 0] = 'X'
  end

  c1 = 'abc'
  assert_raise(IndexError) do
    c1[-10, 0] = 'X'
  end

  d1 = 'abc'
  d1[0, 0] = 'X'
  assert_equal 'Xabc', d1

  e1 = 'abc'
  e1[1, 3] = 'X'
  assert_equal 'aX', e1

  # args is RegExp
  # It will be tested in mrbgems.

  # args is String
  a3 = 'abc'
  a3['bc'] = 'X'
  assert_equal a3, 'aX'

  b3 = 'abc'
  assert_raise(IndexError) do
    b3['XX'] = 'Y'
  end
end

assert('String#capitalize', '15.2.10.5.7') do
  a = 'abc'
  a.capitalize

  assert_equal 'abc', a
  assert_equal 'Abc', 'abc'.capitalize
end

assert('String#capitalize!', '15.2.10.5.8') do
  a = 'abc'
  a.capitalize!

  assert_equal 'Abc', a
  assert_equal nil, 'Abc'.capitalize!
end

assert('String#chomp', '15.2.10.5.9') do
  a = 'abc'.chomp
  b = ''.chomp
  c = "abc\n".chomp
  d = "abc\n\n".chomp
  e = "abc\t".chomp("\t")
  f = "abc\n"

  f.chomp

  assert_equal 'abc', a
  assert_equal '', b
  assert_equal 'abc', c
  assert_equal "abc\n", d
  assert_equal 'abc', e
  assert_equal "abc\n", f
end

assert('String#chomp!', '15.2.10.5.10') do
  a = 'abc'
  b = ''
  c = "abc\n"
  d = "abc\n\n"
  e = "abc\t"

  a.chomp!
  b.chomp!
  c.chomp!
  d.chomp!
  e.chomp!("\t")

  assert_equal 'abc', a
  assert_equal '', b
  assert_equal 'abc', c
  assert_equal "abc\n", d
  assert_equal 'abc', e
end

assert('String#chomp! uses the correct length') do
  class A
    def to_str
      $s.replace("AA")
      "A"
    end
  end

  $s = "AAA"
  $s.chomp!(A.new)
  assert_equal $s, "A"
end

assert('String#chop', '15.2.10.5.11') do
  a = ''.chop
  b = 'abc'.chop
  c = 'abc'

  c.chop

  assert_equal '', a
  assert_equal 'ab', b
  assert_equal 'abc', c
end

assert('String#chop(UTF-8)', '15.2.10.5.11') do
  a = ''.chop
  b = 'あいう'.chop
  c = "あ\nい".chop.chop

  assert_equal '', a
  assert_equal 'あい', b
  assert_equal 'あ', c
end if UTF8STRING

assert('String#chop!', '15.2.10.5.12') do
  a = ''
  b = 'abc'

  a.chop!
  b.chop!

  assert_equal a, ''
  assert_equal b, 'ab'
end

assert('String#chop!(UTF-8)', '15.2.10.5.12') do
  a = ''
  b = "あいうえ\n"
  c = "あいうえ\n"

  a.chop!
  b.chop!
  c.chop!
  c.chop!

  assert_equal a, ''
  assert_equal b, 'あいうえ'
  assert_equal c, 'あいう'
end if UTF8STRING

assert('String#downcase', '15.2.10.5.13') do
  a = 'ABC'.downcase
  b = 'ABC'

  b.downcase

  assert_equal 'abc', a
  assert_equal 'ABC', b
end

assert('String#downcase!', '15.2.10.5.14') do
  a = 'ABC'

  a.downcase!

  assert_equal 'abc', a
  assert_equal nil, 'abc'.downcase!
end

assert('String#each_line', '15.2.10.5.15') do
  a = "first line\nsecond line\nthird line"
  list = ["first line\n", "second line\n", "third line"]
  n_list = []

  a.each_line do |line|
    n_list << line
  end

  assert_equal list, n_list

  n_list.clear
  a.each_line("li") do |line|
    n_list << line
  end
  assert_equal ["first li", "ne\nsecond li", "ne\nthird li", "ne"], n_list
end

assert('String#empty?', '15.2.10.5.16') do
  a = ''
  b = 'not empty'

  assert_true a.empty?
  assert_false b.empty?
end

assert('String#eql?', '15.2.10.5.17') do
  assert_true 'abc'.eql?('abc')
  assert_false 'abc'.eql?('cba')
end

assert('String#gsub', '15.2.10.5.18') do
  assert_equal('aBcaBc', 'abcabc'.gsub('b', 'B'), 'gsub without block')
  assert_equal('aBcaBc', 'abcabc'.gsub('b'){|w| w.capitalize }, 'gsub with block')
  assert_equal('$a$a$',  '#a#a#'.gsub('#', '$'), 'mruby/mruby#847')
  assert_equal('$a$a$',  '#a#a#'.gsub('#'){|_w| '$' }, 'mruby/mruby#847 with block')
  assert_equal('$$a$$',  '##a##'.gsub('##', '$$'), 'mruby/mruby#847 another case')
  assert_equal('$$a$$',  '##a##'.gsub('##'){|_w| '$$' }, 'mruby/mruby#847 another case with block')
  assert_equal('A',      'a'.gsub('a', 'A'))
  assert_equal('A',      'a'.gsub('a'){|w| w.capitalize })
  assert_equal("<a><><>", 'a'.gsub('a', '<\0><\1><\2>'))
  assert_equal(".h.e.l.l.o.", "hello".gsub("", "."))
  a = []
  assert_equal(".h.e.l.l.o.", "hello".gsub("") { |i| a << i; "." })
  assert_equal(["", "", "", "", "", ""], a)
  assert_raise(ArgumentError) { "".gsub }
  assert_raise(ArgumentError) { "".gsub("", "", "") }
end

assert('String#gsub with backslash') do
  s = 'abXcdXef'
  assert_equal 'ab<\\>cd<\\>ef',    s.gsub('X', '<\\\\>')
  assert_equal 'ab<X>cd<X>ef',      s.gsub('X', '<\\&>')
  assert_equal 'ab<X>cd<X>ef',      s.gsub('X', '<\\0>')
  assert_equal 'ab<ab>cd<abXcd>ef', s.gsub('X', '<\\`>')
  assert_equal 'ab<cdXef>cd<ef>ef', s.gsub('X', '<\\\'>')
end

assert('String#gsub!', '15.2.10.5.19') do
  a = 'abcabc'
  a.gsub!('b', 'B')

  b = 'abcabc'
  b.gsub!('b') { |w| w.capitalize }

  assert_equal 'aBcaBc', a
  assert_equal 'aBcaBc', b
end

assert('String#hash', '15.2.10.5.20') do
  a = 'abc'

  assert_equal 'abc'.hash, a.hash
end

assert('String#include?', '15.2.10.5.21') do
  assert_true 'abc'.include?('a')
  assert_false 'abc'.include?('d')
end

assert('String#index', '15.2.10.5.22') do
  assert_equal 0, 'abc'.index('a')
  assert_nil 'abc'.index('d')
  assert_equal 3, 'abcabc'.index('a', 1)
  assert_equal 5, "hello".index("", 5)
  assert_equal nil, "hello".index("", 6)
end

assert('String#initialize', '15.2.10.5.23') do
  a = ''
  a.initialize('abc')
  assert_equal 'abc', a

  a.initialize('abcdefghijklmnopqrstuvwxyz')
  assert_equal 'abcdefghijklmnopqrstuvwxyz', a
end

assert('String#initialize_copy', '15.2.10.5.24') do
  a = ''
  a.initialize_copy('abc')

  assert_equal 'abc', a
end

assert('String#intern', '15.2.10.5.25') do
  assert_equal :abc, 'abc'.intern
end

assert('String#length', '15.2.10.5.26') do
  assert_equal 3, 'abc'.length
end

# 'String#match', '15.2.10.5.27' will be tested in mrbgems.

assert('String#replace', '15.2.10.5.28') do
  a = ''
  a.replace('abc')

  assert_equal 'abc', a
  assert_equal 'abc', 'cba'.replace(a)

  b = 'abc' * 10
  c = ('cba' * 10).dup
  b.replace(c);
  c.replace(b);
  assert_equal c, b

  # shared string
  s = "foo" * 100
  a = s[10, 90]                # create shared string
  assert_equal("", s.replace(""))    # clear
  assert_equal("", s)          # s is cleared
  assert_not_equal("", a)      # a should not be affected
end

assert('String#reverse', '15.2.10.5.29') do
  a = 'abc'
  a.reverse

  assert_equal 'abc', a
  assert_equal 'cba', 'abc'.reverse
end

assert('String#reverse(UTF-8)', '15.2.10.5.29') do
  assert_equal "ち", "こんにちは世界"[3]
  assert_equal nil, "こんにちは世界"[20]
  assert_equal "世", "こんにちは世界"[-2]
  assert_equal "世界", "こんにちは世界"[-2..-1]
  assert_equal "んに", "こんにちは世界"[1,2]
  assert_equal "世", "こんにちは世界"["世"]
end if UTF8STRING

assert('String#reverse!', '15.2.10.5.30') do
  a = 'abc'
  a.reverse!

  assert_equal 'cba', a
  assert_equal 'cba', 'abc'.reverse!
end

assert('String#reverse!(UTF-8)', '15.2.10.5.30') do
  a = 'こんにちは世界!'
  a.reverse!

  assert_equal '!界世はちにんこ', a
  assert_equal '!界世はちにんこ', 'こんにちは世界!'.reverse!
end if UTF8STRING

assert('String#rindex', '15.2.10.5.31') do
  assert_equal 0, 'abc'.rindex('a')
  assert_nil 'abc'.rindex('d')
  assert_equal 0, 'abcabc'.rindex('a', 1)
  assert_equal 3, 'abcabc'.rindex('a', 4)
end

assert('String#rindex(UTF-8)', '15.2.10.5.31') do
  str = "こんにちは世界!\nこんにちは世界!"
  assert_nil str.index('さ')
  assert_equal 3, str.index('ち')
  assert_equal 12, str.index('ち', 10)
  assert_equal nil, str.index("さ")
end if UTF8STRING

# 'String#scan', '15.2.10.5.32' will be tested in mrbgems.

assert('String#size', '15.2.10.5.33') do
  assert_equal 3, 'abc'.size
end

assert('String#size(UTF-8)', '15.2.10.5.33') do
  str = 'こんにちは世界!'
  assert_equal 8, str.size
  assert_not_equal str.bytesize, str.size
  assert_equal 2, str[1, 2].size
end if UTF8STRING

assert('String#slice', '15.2.10.5.34') do
  # length of args is 1
  a = 'abc'.slice(0)
  b = 'abc'.slice(-1)
  c = 'abc'.slice(10)
  d = 'abc'.slice(-10)

  # length of args is 2
  a1 = 'abc'.slice(0, -1)
  b1 = 'abc'.slice(10, 0)
  c1 = 'abc'.slice(-10, 0)
  d1 = 'abc'.slice(0, 0)
  e1 = 'abc'.slice(1, 2)

  # slice of shared string
  e11 = e1.slice(0)

  # args is RegExp
  # It will be tested in mrbgems.

  # args is String
  a3 = 'abc'.slice('bc')
  b3 = 'abc'.slice('XX')

  assert_equal 'a', a
  assert_equal 'c', b
  assert_nil c
  assert_nil d
  assert_nil a1
  assert_nil b1
  assert_nil c1
  assert_equal '', d1
  assert_equal 'bc', e1
  assert_equal 'b', e11
  assert_equal 'bc', a3
  assert_nil b3
end

# TODO Broken ATM
assert('String#split', '15.2.10.5.35') do
  # without RegExp behavior is actually unspecified
  assert_equal ['abc', 'abc', 'abc'], 'abc abc abc'.split
  assert_equal ["a", "b", "c", "", "d"], 'a,b,c,,d'.split(',')
  assert_equal ['abc', 'abc', 'abc'], 'abc abc abc'.split(nil)
  assert_equal ['a', 'b', 'c'], 'abc'.split("")
end

assert('String#split(UTF-8)', '15.2.10.5.35') do
  got = "こんにちは世界!".split('')
  assert_equal ['こ', 'ん', 'に', 'ち', 'は', '世', '界', '!'], got
  got = "こんにちは世界!".split('に')
  assert_equal ['こん', 'ちは世界!'], got
end if UTF8STRING

assert('String#sub', '15.2.10.5.36') do
  assert_equal 'aBcabc', 'abcabc'.sub('b', 'B')
  assert_equal 'aBcabc', 'abcabc'.sub('b') { |w| w.capitalize }
  assert_equal 'aa$', 'aa#'.sub('#', '$')
  assert_equal '.abc', "abc".sub("", ".")

  str = "abc"
  miss = str.sub("X", "Z")
  assert_equal str, miss
  assert_not_equal str.object_id, miss.object_id

  a = []
  assert_equal '.abc', "abc".sub("") { |i| a << i; "." }
  assert_equal [""], a
end

assert('String#sub with backslash') do
  s = 'abXcdXef'
  assert_equal 'ab<\\>cdXef',    s.sub('X', '<\\\\>')
  assert_equal 'ab<X>cdXef',     s.sub('X', '<\\&>')
  assert_equal 'ab<X>cdXef',     s.sub('X', '<\\0>')
  assert_equal 'ab<ab>cdXef',    s.sub('X', '<\\`>')
  assert_equal 'ab<cdXef>cdXef', s.sub('X', '<\\\'>')
end

assert('String#sub!', '15.2.10.5.37') do
  a = 'abcabc'
  a.sub!('b', 'B')

  b = 'abcabc'
  b.sub!('b') { |w| w.capitalize }

  assert_equal 'aBcabc', a
  assert_equal 'aBcabc', b
end

assert('String#to_f', '15.2.10.5.38') do
  a = ''.to_f
  b = '123456789'.to_f
  c = '12345.6789'.to_f
  d = '1e-2147483648'.to_f
  e = '1e2147483648'.to_f

  assert_float(0.0, a)
  assert_float(123456789.0, b)
  assert_float(12345.6789, c)
  assert_float(0, d)
  assert_float(Float::INFINITY, e)
end if class_defined?("Float")

assert('String#to_i', '15.2.10.5.39') do
  a = ''.to_i
  b = '32143'.to_i
  c = 'a'.to_i(16)
  d = '100'.to_i(2)
  e = '1_000'.to_i

  assert_equal 0, a
  assert_equal 32143, b
  assert_equal 10, c
  assert_equal 4, d
  assert_equal 1_000, e
end

assert('String#to_s', '15.2.10.5.40') do
  assert_equal 'abc', 'abc'.to_s
end

assert('String#to_sym', '15.2.10.5.41') do
  assert_equal :abc, 'abc'.to_sym
end

assert('String#upcase', '15.2.10.5.42') do
  a = 'abc'.upcase
  b = 'abc'

  b.upcase

  assert_equal 'ABC', a
  assert_equal 'abc', b
end

assert('String#upcase!', '15.2.10.5.43') do
  a = 'abc'

  a.upcase!

  assert_equal 'ABC', a
  assert_equal nil, 'ABC'.upcase!

  a = 'abcdefghijklmnopqrstuvwxyz'
  b = a.dup
  a.upcase!
  b.upcase!
  assert_equal 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', b
end

assert('String#inspect', '15.2.10.5.46') do
  # should not raise an exception - regress #1210
  assert_nothing_raised do
  ("\1" * 100).inspect
  end

  assert_equal "\"\\x00\"", "\0".inspect
end

# Not ISO specified

assert('String interpolation (mrb_str_concat for shared strings)') do
  a = "A" * 32
  assert_equal "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:", "#{a}:"
end

assert('Check the usage of a NUL character') do
  "qqq\0ppp"
end

assert('String#bytes') do
  str1 = "hello"
  bytes1 = [104, 101, 108, 108, 111]

  str2 = "\xFF"
  bytes2 = [0xFF]

  assert_equal bytes1, str1.bytes
  assert_equal bytes2, str2.bytes
end

assert('String#each_byte') do
  str1 = "hello"
  bytes1 = [104, 101, 108, 108, 111]
  bytes2 = []

  str1.each_byte {|b| bytes2 << b }

  assert_equal bytes1, bytes2
end

assert('String#freeze') do
  str = "hello"
  str.freeze

  assert_raise(RuntimeError) { str.upcase! }
end
