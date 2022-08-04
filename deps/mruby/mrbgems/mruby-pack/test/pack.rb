# coding: utf-8
PACK_IS_LITTLE_ENDIAN = "\x01\00".unpack('S')[0] == 0x01

def assert_pack tmpl, packed, unpacked
  t = tmpl.inspect
  assert "assert_pack" do
    assert_equal packed, unpacked.pack(tmpl), "#{unpacked.inspect}.pack(#{t})"
    assert_equal unpacked, packed.unpack(tmpl), "#{packed.inspect}.unpack(#{t})"
  end
end

# pack & unpack 'm' (base64)
assert('pack("m")') do
  assert_pack "m", "", [""]
  assert_pack "m", "AA==\n", ["\0"]
  assert_pack "m", "AAA=\n", ["\0\0"]
  assert_pack "m", "AAAA\n", ["\0\0\0"]
  assert_pack "m", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJT\nVFVWV1hZWg==\n", ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]

  ary = ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
  assert_equal ary, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJT\nVFVWV1hZWg==\n".unpack("m")
  assert_equal ary, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWg==\n".unpack("m")

  assert_equal "QQ==\n", ["A", "B"].pack("m50")
  assert_equal ["A"], "QQ==\n".unpack("m50")
  assert_equal "QQ==Qg==", ["A", "B"].pack("m0 m0")
  assert_equal ["A", "B"], "QQ==Qg==".unpack("m10 m10")
  assert_pack "m0", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWg==", ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
end

# pack & unpack 'M' (Quoted-printable)
assert('pack("M")') do
  assert_pack "M", "123=\n", ["123"]
  assert_pack "M", "=3D\n", ["=\n"]
  assert_pack "M", "=E3=81=82=\n", ["あ"]

  assert_equal ["123"], "123=\n".unpack("M")
  assert_equal ["=\n"], "=3D\n".unpack("M")
  assert_equal ["あ"], "=E3=81=82=\n".unpack("M")
end

# pack & unpack 'H'
assert('pack("H")') do
  assert_pack "H*", "01", ["3031"]
  assert_pack "H*", "\020", ["10"]
end

assert('pack("C")') do
  assert_pack "C*", "\x00\x01\x7F\x80\xFF", [0, 1, 127, 128, 255]
end

assert('pack("a")') do
  assert_equal "a", ["abc"].pack("a")
  assert_equal "abc", ["abc"].pack("a*")
  assert_equal "abc\0", ["abc"].pack("a4")

  assert_equal ["abc\0"], "abc\0".unpack("a4")
  assert_equal ["abc "], "abc ".unpack("a4")
end

assert('pack("A")') do
  assert_equal "a", ["abc"].pack("A")
  assert_equal "abc", ["abc"].pack("A*")
  assert_equal "abc ", ["abc"].pack("A4")

  assert_equal ["abc"], "abc\0".unpack("A4")
  assert_equal ["abc"], "abc ".unpack("A4")
end

# regression tests
assert('issue #1') do
  assert_equal "\000\001\000\002", [1, 2].pack("nn")
end

assert 'pack float' do
  skip unless Object.const_defined?(:Float)
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
  skip unless Object.const_defined?(:Float)
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
    str = "\xFF" * (int_size-2) + "\xCF\xC7"
  end
  assert_pack 'i', str, [-12345]
end

assert 'pack/unpack "I"' do
  uint_size = [0].pack('I').size
  raise "pack('I').size is too small (#{uint_size})" if uint_size < 2

  if PACK_IS_LITTLE_ENDIAN
    str = "\x39\x30" + "\0" * (uint_size-2)
  else
    str = "\0" * (uint_size-2) + "\x30\x39"
  end
  assert_pack 'I', str, [12345]
end

assert 'pack/unpack "w"' do
  for x in [0,1,127,128,16383,16384,65535,65536]
    assert_equal [x], [x].pack("w").unpack("w")
  end
end

assert 'pack/unpack "U"' do
  assert_equal [], "".unpack("U")
  assert_equal [], "".unpack("U*")
  assert_equal [65, 66], "ABC".unpack("U2")
  assert_equal [12371, 12435, 12395, 12385, 12399, 19990, 30028], "こんにちは世界".unpack("U*")

  assert_equal "", [].pack("U")
  assert_equal "", [].pack("U*")
  assert_equal "AB", [65, 66, 67].pack("U2")
  assert_equal "こんにちは世界", [12371, 12435, 12395, 12385, 12399, 19990, 30028].pack("U*")

  assert_equal "\000", [0].pack("U")

  assert_raise(RangeError) { [-0x40000000].pack("U") }
  assert_raise(RangeError) { [-1].pack("U") }
  assert_raise(RangeError) { [0x40000000].pack("U") }
end
