# pack & unpack 'm' (base64)
assert('[""].pack("m")') do
  ary = ""
  str = ""
  [ary].pack("m") == str and
  str.unpack("m") == [ary]
end

assert('["\0"].pack("m")') do
  ary = "\0"
  str = "AA==\n"
  [ary].pack("m") == str and
  str.unpack("m") == [ary]
end

assert('["\0\0"].pack("m")') do
  ary = "\0\0"
  str = "AAA=\n"
  [ary].pack("m") == str and
  str.unpack("m") == [ary]
end

assert('["\0\0\0"].pack("m")') do
  ary = "\0\0\0"
  str = "AAAA\n"
  [ary].pack("m") == str and
  str.unpack("m") == [ary]
end

assert('["abc..xyzABC..XYZ"].pack("m")') do
  ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"].pack("m") == "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJT\nVFVWV1hZWg==\n"
end

assert('"YWJ...".unpack("m") should "abc..xyzABC..XYZ"') do
  str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJT\nVFVWV1hZWg==\n".unpack("m") == [str] and
  "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWg==\n".unpack("m") == [str]
end

# pack & unpack 'H'
assert('["3031"].pack("H*")') do
  ary = "3031"
  str = "01"
  [ary].pack("H*") == str and
  str.unpack("H*") == [ary]
end

assert('["10"].pack("H*")') do
  ary = "10"
  str = "\020"
  [ary].pack("H*") == str and
  str.unpack("H*") == [ary]
end

assert('[0,1,127,128,255].pack("C*")') do
 ary = [ 0, 1, 127, 128, 255 ]
 str = "\x00\x01\x7F\x80\xFF"
 ary.pack("C*") == str and str.unpack("C*") == ary
end

# pack "a"
assert('["abc"].pack("a")') do
  ["abc"].pack("a") == "a" and
  ["abc"].pack("a*") == "abc" and
  ["abc"].pack("a4") == "abc\0"
end

# upack "a"
assert('["abc"].pack("a")') do
  "abc\0".unpack("a4") == ["abc\0"] and
  "abc ".unpack("a4") == ["abc "]
end

# pack "A"
assert('["abc"].pack("A")') do
  ["abc"].pack("A") == "a" and
  ["abc"].pack("A*") == "abc" and
  ["abc"].pack("A4") == "abc "
end

# upack "A"
assert('["abc"].pack("A")') do
  "abc\0".unpack("A4") == ["abc"] and
  "abc ".unpack("A4") == ["abc"]
end

# regression tests
assert('issue #1') do
  [1, 2].pack("nn") == "\000\001\000\002"
end

def assert_pack tmpl, packed, unpacked
  assert_equal packed, unpacked.pack(tmpl)
  assert_equal unpacked, packed.unpack(tmpl)
end

PACK_IS_LITTLE_ENDIAN = "\x01\00".unpack('S')[0] == 0x01

assert 'pack float' do
  assert_pack 'e', "\x00\x00@@", [3.0]
  assert_pack 'g', "@@\x00\x00", [3.0]

  if PACK_IS_LITTLE_ENDIAN
    assert_pack 'f', "\x00\x00@@", [3.0]
    assert_pack 'F', "\x00\x00@@", [3.0]
  else
    assert_pack 'f', "@@\x00\x00", [3.0]
    assert_pack 'F', "@@\x00\x00", [3.0]
  end
end

assert 'pack double' do
  assert_pack 'E', "\x00\x00\x00\x00\x00\x00\b@", [3.0]
  assert_pack 'G', "@\b\x00\x00\x00\x00\x00\x00", [3.0]

  if PACK_IS_LITTLE_ENDIAN
    assert_pack 'd', "\x00\x00\x00\x00\x00\x00\b@", [3.0]
    assert_pack 'D', "\x00\x00\x00\x00\x00\x00\b@", [3.0]
  else
    assert_pack 'd', "@\b\x00\x00\x00\x00\x00\x00", [3.0]
    assert_pack 'D', "@\b\x00\x00\x00\x00\x00\x00", [3.0]
  end
end

assert 'pack/unpack "i"' do
  int_size = [0].pack('i').size
  raise "pack('i').size is too small (#{int_size})" if int_size < 2

  if PACK_IS_LITTLE_ENDIAN
    str = "\xC7\xCF" + "\xFF" * (int_size-2)
  else
    str = "\xFF" * (int_size-2) + "\xC7\xCF"
  end
  assert_pack 'i', str, [-12345]
end

assert 'pack/unpack "I"' do
  uint_size = [0].pack('I').size
  raise "pack('I').size is too small (#{uint_size})" if uint_size < 2

  if PACK_IS_LITTLE_ENDIAN
    str = "\x39\x30" + "\0" * (uint_size-2)
  else
    str = "\0" * (uint_size-2) + "\x39\x30"
  end
  assert_pack 'I', str, [12345]
end
