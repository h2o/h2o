# encoding: ascii

# a = Array, s = String, t = Template

def packtest(a, s, t)
  begin
    r = a.pack(t)
    return if r == s
    puts "#{a.inspect}.pack(#{t.inspect}) -> #{r.inspect} should be #{s.inspect}"
  rescue => r
    unless r.is_a? s
      puts "#{a.inspect}.pack(#{t.inspect}) -> #{r.inspect} should be #{s.inspect}"
    end
  end
end

def unpacktest(a, s, t)
  r = s.unpack(t)
  return if r == a
  puts "#{s.inspect}.unpack(#{t.inspect}) -> #{r.inspect} should be #{a.inspect}"
end

def pptest(a, s, t)
  packtest(a, s, t)
  unpacktest(a, s, t)
end

pptest [1], "\x01", "C"

packtest [1.1], "\x01", "C"
packtest [-1], "\xff", "C"
packtest [1,2], "\x01\x02", "C2"
#packtest [1], "X", ArgumentError

unpacktest [48, nil], "0", "CC"
unpacktest [160, -96], "\xa0\xa0", "Cc"
unpacktest [49, 50, 51], "123", "C*"

pptest [12849], "12", "S"
unpacktest [nil], "0", "S"
unpacktest [12849, nil], "123", "SS"
unpacktest [12849], "123", "S*"

pptest [10000], "\x27\x10", "s>"
pptest [-10000], "\xd8\xf0", "s>"
pptest [50000], "\xc3\x50", "S>"

pptest [10000], "\x10\x27", "s<"
pptest [-10000], "\xf0\xd8", "s<"
pptest [50000], "\x50\xc3", "S<"

pptest [1000000000], "\x3b\x9a\xca\x00", "l>"
pptest [-1000000000], "\xc4\x65\x36\x00", "l>"

pptest [1], "\x01\x00\x00\x00", "L<"
pptest [258], "\x02\x01\x00\x00", "L<"
pptest [66051], "\x03\x02\x01\x00", "L<"
pptest [16909060], "\x04\x03\x02\x01", "L<"
pptest [16909060], "\x01\x02\x03\x04", "L>"

packtest [-1], "\xff\xff\xff\xff", "L<"

pptest [1000000000], "\x00\x00\x00\x00\x3b\x9a\xca\x00", "q>"
pptest [-1000000000], "\xff\xff\xff\xff\xc4\x65\x36\x00", "q>"

if (2**33).is_a? Fixnum
  pptest [81985529216486895],    "\x01\x23\x45\x67\x89\xab\xcd\xef", "q>"
  pptest [-1167088121787636991], "\x01\x23\x45\x67\x89\xab\xcd\xef", "q<"
end

pptest [16909060], "\x01\x02\x03\x04", "N"
pptest [258], "\x01\x02", "n"
pptest [32769], "\x80\x01", "n"

pptest [16909060], "\x04\x03\x02\x01", "V"
pptest [258], "\x02\x01", "v"

packtest [""], "", "m"
packtest ["a"], "YQ==\n", "m"
packtest ["ab"], "YWI=\n", "m"
packtest ["abc"], "YWJj\n", "m"
packtest ["abcd"], "YWJjZA==\n", "m"

unpacktest [""], "", "m"
unpacktest ["a"], "YQ==\n", "m"
unpacktest ["ab"], "YWI=\n", "m"
unpacktest ["abc"], "YWJj\n", "m"
unpacktest ["abcd"], "YWJjZA==\n", "m"

packtest [""], "\0", "H"
packtest ["3"], "0", "H"
packtest ["34"], "", "H0"
packtest ["34"], "0", "H"
packtest ["34"], "4", "H2"
packtest ["34"], "4\0", "H3"
packtest ["3456"], "4P", "H3"
packtest ["34563"], "4V0", "H*"
packtest ["5a"], "Z", "H*"
packtest ["5A"], "Z", "H*"

unpacktest [""], "", "H"
unpacktest [""], "0", "H0"
unpacktest ["3"], "0", "H"
unpacktest ["30"], "0", "H2"
unpacktest ["30"], "0", "H3"
unpacktest ["303"], "01", "H3"
unpacktest ["303132"], "012", "H*"
unpacktest ["3031", 50], "012", "H4C"
unpacktest ["5a"], "Z", "H*"

packtest [""], "\0", "h"
packtest ["3"], "\03", "h"
packtest ["34"], "", "h0"
packtest ["34"], "\03", "h"
packtest ["34"], "C", "h2"
packtest ["34"], "C\0", "h3"
packtest ["3456"], "C\05", "h3"
packtest ["34563"], "Ce\03", "h*"

packtest   [""],    " ",   "A"
unpacktest [""],    "",    "A"
pptest     ["1"],   "1",   "A"
pptest     ["1"],   "1 ",  "A2"
unpacktest ["1"],   "1",   "A2"
unpacktest ["1"],   "1 ",  "A2"
unpacktest ["1"],   "1\0", "A2"
packtest   ["12"],  "1",   "A"
unpacktest ["1"],   "12",  "A"
pptest     ["123"], "123", "A*"
packtest   ["1","2"], "2", "A0A"
unpacktest ["","2"],  "2", "A0A"

packtest   [""],    "\0",  "a"
unpacktest [""],    "",    "a"
pptest     ["1"],   "1",   "a"
pptest     ["1 "],  "1 ",  "a2"
pptest     ["1\0"], "1\0", "a2"
packtest   ["1"],   "1\0", "a2"
pptest     ["123"], "123", "a*"

packtest   [""],    "\0",    "Z"
unpacktest [""],    "",      "Z"
pptest     ["1"],   "1",     "Z"
pptest     ["1"],   "1\0",   "Z2"
pptest     ["1 "],  "1 ",    "Z2"
pptest     ["123"], "123\0", "Z*"
pptest     ["1","2"], "12",      "ZZ"
pptest     ["1","2"], "1\0002",  "Z*Z"
unpacktest ["1","3"], "1\00023", "Z3Z"

packtest   [1, 2], "\x01\x02", "CyC"

packtest   [65], "A", 'U'
packtest   [59411], "\xEE\xA0\x93", 'U'

pptest     [1], "\x00\x01", "xC"
unpacktest [2], "\xcc\x02", "xC"
