
# Constant
assert("OnigRegexp::CONSTANT") do
  OnigRegexp::IGNORECASE == 1 and OnigRegexp::EXTENDED == 2 and OnigRegexp::MULTILINE == 4
end


# Class method
assert('OnigRgexp.compile', '15.2.15.6.2') do
  assert_equal OnigRegexp.compile('.*'), OnigRegexp.compile('.*')
end

assert('OnigRegexp.escape', '15.2.15.6.2') do
  escaping_chars = "\n\t\r\f #$()*+-.?[\\]^{|}"
  assert_equal '\n\t\r\f\\ \#\$\(\)\*\+\-\.\?\[\\\\\]\^\{\|\}', OnigRegexp.escape(escaping_chars)
  assert_equal 'cute\nmruby\tcute', OnigRegexp.escape("cute\nmruby\tcute")
end

assert('OnigRegexp.last_match', '15.2.15.6.3') do
  OnigRegexp.new('.*') =~ 'ginka'
  assert_equal 'ginka', OnigRegexp.last_match[0]
end

assert('OnigRegexp.quote', '15.2.15.6.4') do
  assert_equal '\n', OnigRegexp.quote("\n")
end

# Instance method
assert('OnigRegexp#initialize', '15.2.15.7.1') do
  OnigRegexp.new(".*") and OnigRegexp.new(".*", OnigRegexp::MULTILINE)
end

assert('OnigRegexp#initialize_copy', '15.2.15.7.2') do
  r1 = OnigRegexp.new(".*")
  r2 = r1.dup
  assert_equal r1, r2
  assert_equal 'kawa', r2.match('kawa')[0]
end

assert("OnigRegexp#==", '15.2.15.7.3') do
  reg1 = reg2 = OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+")
  reg3 = OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+")
  reg4 = OnigRegexp.new("(https://[^/]+)[-a-zA-Z0-9./]+")

  assert_true(reg1 == reg2 && reg1 == reg3 && !(reg1 == reg4))

  assert_false(OnigRegexp.new("a") == "a")
end

assert("OnigRegexp#===", '15.2.15.7.4') do
  reg = OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+")
  assert_true reg === "http://example.com"
  assert_false reg === "htt://example.com"
end

assert('OnigRegexp#=~', '15.2.15.7.5') do
  assert_equal(0) { OnigRegexp.new('.*') =~ 'akari' }
  assert_equal(nil) { OnigRegexp.new('t') =~ 'akari' }
end

assert("OnigRegexp#casefold?", '15.2.15.7.6') do
  assert_false OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+", OnigRegexp::MULTILINE).casefold?
  assert_true OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+", OnigRegexp::IGNORECASE | OnigRegexp::EXTENDED).casefold?
  assert_true OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+", OnigRegexp::MULTILINE | OnigRegexp::IGNORECASE).casefold?
  assert_false OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+").casefold?
  assert_true OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+", true).casefold?
end

assert("OnigRegexp#match", '15.2.15.7.7') do
  reg = OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+")
  assert_false reg.match("http://masamitsu-murase.12345/hoge.html").nil?
  assert_nil reg.match("http:///masamitsu-murase.12345/hoge.html")
end

assert("OnigRegexp#source", '15.2.15.7.8') do
  str = "(https?://[^/]+)[-a-zA-Z0-9./]+"
  reg = OnigRegexp.new(str)

  reg.source == str
end

if OnigRegexp.const_defined? :ASCII_RANGE
  assert('OnigRegexp#options (no options)') do
    assert_equal OnigRegexp::ASCII_RANGE | OnigRegexp::POSIX_BRACKET_ALL_RANGE | OnigRegexp::WORD_BOUND_ALL_RANGE, OnigRegexp.new(".*").options
  end

  assert('OnigRegexp#options (multiline)') do
    assert_equal OnigRegexp::MULTILINE | OnigRegexp::ASCII_RANGE | OnigRegexp::POSIX_BRACKET_ALL_RANGE | OnigRegexp::WORD_BOUND_ALL_RANGE, OnigRegexp.new(".*", OnigRegexp::MULTILINE).options
  end
end

assert("OnigRegexp#inspect") do
  reg = OnigRegexp.new("(https?://[^/]+)[-a-zA-Z0-9./]+")

  assert_equal '/(https?:\/\/[^\/]+)[-a-zA-Z0-9.\/]+/', reg.inspect
  assert_equal '/abc\nd\te/mi', OnigRegexp.new("abc\nd\te", OnigRegexp::MULTILINE | OnigRegexp::IGNORECASE).inspect
  assert_equal '/abc/min', OnigRegexp.new("abc", OnigRegexp::MULTILINE | OnigRegexp::IGNORECASE, "none").inspect
end

assert("OnigRegexp#to_s") do
  assert_equal '(?-mix:ab+c)', OnigRegexp.new("ab+c").to_s
  assert_equal '(?-mix:ab+c)', /ab+c/.to_s
  assert_equal '(?mx-i:ab+c)', OnigRegexp.new("ab+c", OnigRegexp::MULTILINE | OnigRegexp::EXTENDED).to_s
  assert_equal '(?mi-x:ab+c)', /ab+c/im.to_s
  assert_equal '(?mi-x:ab+c)', /ab+c/imn.to_s
end

assert("OnigRegexp#to_s (composition)") do
  re1 = OnigRegexp.new("ab+c")
  re2 = OnigRegexp.new("xy#{re1}z")
  assert_equal '(?-mix:xy(?-mix:ab+c)z)', re2.to_s

  re3 = OnigRegexp.new("ab.+c", OnigRegexp::MULTILINE)
  re4 = OnigRegexp.new("xy#{re3}z", OnigRegexp::IGNORECASE)
  assert_equal '(?i-mx:xy(?m-ix:ab.+c)z)', re4.to_s
end

# Extended patterns.
assert("OnigRegexp#match (no flags)") do
  [
    [ ".*", "abcd\nefg", "abcd" ],
    [ "^a.", "abcd\naefg", "ab" ],
    [ "^a.", "bacd\naefg", "ae" ],
    [ ".$", "bacd\naefg", "d" ]
  ].each do |reg, str, result|
    m = OnigRegexp.new(reg).match(str)
    assert_equal result, m[0] if assert_false m.nil?
  end
end

assert("OnigRegexp#match (multiline)") do
  patterns = [
    [ OnigRegexp.new(".*", OnigRegexp::MULTILINE), "abcd\nefg", "abcd\nefg" ]
  ]

  patterns.all?{ |reg, str, result| reg.match(str)[0] == result }
end

assert("OnigRegexp#match (ignorecase)") do
  [
    [ "aBcD", "00AbcDef", "AbcD" ],
    [ "0x[a-f]+", "00XaBCdefG", "0XaBCdef" ],
    [ "0x[^c-f]+", "00XaBCdefG", "0XaB" ]
  ].each do |reg, str, result|
    m = OnigRegexp.new(reg, OnigRegexp::IGNORECASE|OnigRegexp::EXTENDED).match(str)
    assert_equal result, m[0] if assert_false m.nil?
  end
end

assert("OnigRegexp#match (none encoding)") do
  assert_equal 2, /\x82/n =~ "あ"
end

assert('OnigRegexp.version') do
  OnigRegexp.version.kind_of? String
end

def onig_match_data_example
  OnigRegexp.new('(\w+)(\w)').match('+aaabb-')
end

assert('OnigMatchData.new') do
  assert_raise(NoMethodError) { OnigMatchData.new('aaa', 'i') }
end

assert('OnigMatchData#[]', '15.2.16.3.1') do
  m = onig_match_data_example
  assert_equal 'aaabb', m[0]
  assert_equal 'aaab', m[1]
  assert_equal 'b', m[2]
  assert_nil m[3]

  m = OnigRegexp.new('(?<name>\w\w)').match('aba')
  assert_raise(TypeError) { m[[]] }
  assert_raise(IndexError) { m['nam'] }
  assert_equal 'ab', m[:name]
  assert_equal 'ab', m['name']
  assert_equal 'ab', m[1]

  m = OnigRegexp.new('(\w) (\w) (\w) (\w)').match('a b c d')
  assert_equal %w(a b c d), m[1..-1]
end

assert('OnigMatchData#begin', '15.2.16.3.2') do
  m = onig_match_data_example
  assert_equal 1, m.begin(0)
  assert_equal 1, m.begin(1)
  assert_raise(IndexError) { m.begin 3 }
end

assert('OnigMatchData#captures', '15.2.16.3.3') do
  m = onig_match_data_example
  assert_equal ['aaab', 'b'], m.captures

  m = OnigRegexp.new('(\w+)(\d)?').match('+aaabb-')
  assert_equal ['aaabb', nil], m.captures
end

assert('OnigMatchData#end', '15.2.16.3.4') do
  m = onig_match_data_example
  assert_equal 6, m.end(0)
  assert_equal 5, m.end(1)
  assert_raise(IndexError) { m.end 3 }
end

assert('OnigMatchData#initialize_copy', '15.2.16.3.5') do
  m = onig_match_data_example
  c = m.dup
  assert_equal m.to_a, c.to_a
end

assert('OnigMatchData#length', '15.2.16.3.6') do
  assert_equal 3, onig_match_data_example.length
end

assert('OnigMatchData#offset', '15.2.16.3.7') do
  assert_equal [1, 6], onig_match_data_example.offset(0)
  assert_equal [1, 5], onig_match_data_example.offset(1)
end

assert('OnigMatchData#post_match', '15.2.16.3.8') do
  assert_equal '-', onig_match_data_example.post_match
end

assert('OnigMatchData#pre_match', '15.2.16.3.9') do
  assert_equal '+', onig_match_data_example.pre_match
end

assert('OnigMatchData#size', '15.2.16.3.10') do
  assert_equal 3, onig_match_data_example.length
end

assert('OnigMatchData#string', '15.2.16.3.11') do
  assert_equal '+aaabb-', onig_match_data_example.string
end

assert('OnigMatchData#to_a', '15.2.16.3.12') do
  assert_equal ['aaabb', 'aaab', 'b'], onig_match_data_example.to_a
end

assert('OnigMatchData#to_s', '15.2.16.3.13') do
  assert_equal 'aaabb', onig_match_data_example.to_s
end

assert('OnigMatchData#regexp') do
  assert_equal '(\w+)(\w)', onig_match_data_example.regexp.source
end

assert('Invalid regexp') do
  assert_raise(ArgumentError) { OnigRegexp.new '[aio' }
end

assert('String#onig_regexp_gsub') do
  test_str = 'hello mruby'
  assert_equal 'h*ll* mr*by', test_str.onig_regexp_gsub(OnigRegexp.new('[aeiou]'), '*')
  assert_equal 'h<e>ll<o> mr<u>by', test_str.onig_regexp_gsub(OnigRegexp.new('([aeiou])'), '<\1>')
  assert_equal 'h e l l o  m r u b y ', test_str.onig_regexp_gsub(OnigRegexp.new('\w')) { |v| v + ' ' }
  assert_equal 'h{e}ll{o} mr{u}by', test_str.onig_regexp_gsub(OnigRegexp.new('(?<hoge>[aeiou])'), '{\k<hoge>}')
  assert_equal '.h.e.l.l.o. .m.r.u.b.y.', test_str.onig_regexp_gsub(OnigRegexp.new(''), '.')
  assert_equal " hello\n mruby", "hello\nmruby".onig_regexp_gsub(OnigRegexp.new('^'), ' ')
  assert_equal "he<l><><l><>o mruby", test_str.onig_regexp_gsub(OnigRegexp.new('(l)'), '<\1><\2>')
end

assert('String#onig_regexp_scan') do
  test_str = 'mruby world'
  assert_equal ['mruby', 'world'], test_str.onig_regexp_scan(OnigRegexp.new('\w+'))
  assert_equal ['mru', 'by ', 'wor'], test_str.onig_regexp_scan(OnigRegexp.new('...'))
  assert_equal [['mru'], ['by '], ['wor']], test_str.onig_regexp_scan(OnigRegexp.new('(...)'))
  assert_equal [['mr', 'ub'], ['y ', 'wo']], test_str.onig_regexp_scan(OnigRegexp.new('(..)(..)'))

  result = []
  assert_equal test_str, test_str.onig_regexp_scan(OnigRegexp.new('\w+')) { |v| result << "<<#{v}>>" }
  assert_equal ['<<mruby>>', '<<world>>'], result

  result = ''
  assert_equal test_str, test_str.onig_regexp_scan(OnigRegexp.new('(.)(.)')) { |x, y| result += y; result += x }
  assert_equal 'rmbu yowlr', result
end

assert('String#onig_regexp_sub') do
  test_str = 'hello mruby'
  assert_equal 'h*llo mruby', test_str.onig_regexp_sub(OnigRegexp.new('[aeiou]'), '*')
  assert_equal 'h<e>llo mruby', test_str.onig_regexp_sub(OnigRegexp.new('([aeiou])'), '<\1>')
  assert_equal 'h ello mruby', test_str.onig_regexp_sub(OnigRegexp.new('\w')) { |v| v + ' ' }
  assert_equal 'h{e}llo mruby', test_str.onig_regexp_sub(OnigRegexp.new('(?<hoge>[aeiou])'), '{\k<hoge>}')
end

assert('String#onig_regexp_split') do
  test_str = 'cute mruby cute'
  assert_equal ['cute', 'mruby', 'cute'], test_str.onig_regexp_split
  assert_equal ['cute', 'mruby', 'cute'], test_str.onig_regexp_split(OnigRegexp.new(' '))

  prev_splitter = $;
  $; = OnigRegexp.new ' \w'
  assert_equal ['cute', 'ruby', 'ute'], test_str.onig_regexp_split
  $; = 't'
  assert_equal ['cu', 'e mruby cu', 'e'], test_str.onig_regexp_split
  $; = prev_splitter

  assert_equal ['h', 'e', 'l', 'l', 'o'], 'hello'.onig_regexp_split(OnigRegexp.new(''))
  assert_equal ['h', 'e', 'llo'], 'hello'.onig_regexp_split(OnigRegexp.new(''), 3)
  assert_equal ['h', 'i', 'd', 'a', 'd'], 'hi dad'.onig_regexp_split(OnigRegexp.new('\s*'))

  test_str = '1, 2, 3, 4, 5,, 6'
  assert_equal ['1', '2', '3', '4', '5', '', '6'], test_str.onig_regexp_split(OnigRegexp.new(',\s*'))

  test_str = '1,,2,3,,4,,'
  assert_equal ['1', '', '2', '3', '', '4'], test_str.onig_regexp_split(OnigRegexp.new(','))
  assert_equal ['1', '', '2', '3,,4,,'], test_str.onig_regexp_split(OnigRegexp.new(','), 4)
  assert_equal ['1', '', '2', '3', '', '4', '', ''], test_str.onig_regexp_split(OnigRegexp.new(','), -4)

  assert_equal [], ''.onig_regexp_split(OnigRegexp.new(','), -1)
end

assert('String#index') do
  assert_equal 0, 'abc'.index('a')
  assert_nil 'abc'.index('d')
  assert_equal 3, 'abcabc'.index('a', 1)
  assert_equal 1, "hello".index(?e)

  assert_equal 0, 'abcabc'.index(/a/)
  assert_nil 'abc'.index(/d/)
  assert_equal 3, 'abcabc'.index(/a/, 1)
  assert_equal 4, "hello".index(/[aeiou]/, -3)
  assert_equal 3, "regexpindex".index(/e.*x/, 2)
end

prev_regexp = Regexp

Regexp = OnigRegexp

# global variables
assert('$~') do
  m = onig_match_data_example
  assert_equal m[0], $~[0]
end

assert('$&') do
  m = onig_match_data_example
  assert_equal m[0], $&
end

assert('$`') do
  m = onig_match_data_example
  assert_equal m.pre_match, $`
end

assert('$\'') do
  m = onig_match_data_example
  assert_equal m.post_match, $'
end

assert('$+') do
  m = onig_match_data_example
  assert_equal m[-1], $+
end

assert('$1 to $9') do
  onig_match_data_example
  assert_equal 'aaab', $1
  assert_equal 'b', $2
  assert_nil $3
  assert_nil $4
  assert_nil $5
  assert_nil $6
  assert_nil $7
  assert_nil $8
  assert_nil $9
end

assert('default OnigRegexp.set_global_variables?') do
  assert_true OnigRegexp.set_global_variables?
end

assert('change set_global_variables') do
  m = onig_match_data_example
  assert_equal m[0], $~[0]

  OnigRegexp.set_global_variables = false
  assert_false OnigRegexp.set_global_variables?

  # global variables must be cleared when OnigRegexp.set_global_variables gets change
  assert_nil $~

  onig_match_data_example
  assert_nil $~

  OnigRegexp.set_global_variables = true
end

Regexp = Object

assert('OnigRegexp not default') do
  onig_match_data_example
  assert_nil $~
end

Regexp = prev_regexp
