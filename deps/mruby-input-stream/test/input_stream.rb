assert('InputStream.new()') do
  vec = InputStream.new
  assert_equal InputStream, vec.class
end

assert('InputStream.new("foo")') do
  vec = InputStream.new("foo")
  assert_equal InputStream, vec.class
end

assert('InputStream#read') do
  vec = InputStream.new("foo")
  assert_equal "foo", vec.read
end

assert('InputStream#read(2)') do
  vec = InputStream.new("abcdef")
  assert_equal "ab", vec.read(2)
  assert_equal "cde", vec.read(3)
  assert_equal "f", vec.read(4)
  assert_equal nil, vec.read(5)
end

assert('InputStream#read(2, "")') do
  vec = InputStream.new("abcdef")
  s1 = ""
  assert_equal "ab", vec.read(2, s1)
  assert_equal "ab", s1
  assert_equal "abcde", vec.read(3, s1)
  assert_equal "abcde", s1
  assert_equal "abcdef", vec.read(4, s1)
  assert_equal "abcdef", s1
  assert_equal nil, vec.read(5, s1)
  assert_equal "abcdef", s1
end

assert('InputStream#read(10)') do
  vec = InputStream.new("abc")
  assert_equal "abc", vec.read(10)
  assert_equal nil, vec.read(10)
end

assert('InputStream#read ""') do
  vec = InputStream.new("")
  assert_equal nil, vec.read(2)
  assert_equal nil, vec.read(0)
  assert_equal nil, vec.read(2)
end

assert('InputStream#read(0)') do
  vec = InputStream.new("foo")
  assert_equal "", vec.read(0)
  assert_equal "", vec.read(0)
  assert_equal "f", vec.read(1)
end


assert('InputStream#gets') do
  vec = InputStream.new("foo")
  assert_equal "foo", vec.gets
  assert_equal nil, vec.gets
end

assert('InputStream#gets ""') do
  vec = InputStream.new("")
  assert_equal nil, vec.gets
end

assert('InputStream#gets long') do
  vec = InputStream.new("foo\nbar\nbuz\n")
  assert_equal "foo\n", vec.gets
  assert_equal "bar\n", vec.gets
  assert_equal "buz\n", vec.gets
  assert_equal nil, vec.gets
end

assert('InputStream#gets NN') do
  vec = InputStream.new("\n\nbuz")
  assert_equal "\n", vec.gets
  assert_equal "\n", vec.gets
  assert_equal "buz", vec.gets
  assert_equal nil, vec.gets
end

assert('InputStream#each') do
  vec = InputStream.new("foo\nbar\nbuz\nzzz")
  buf = []
  vec.each do |line|
    buf << line
  end
  assert_equal ["foo\n", "bar\n", "buz\n", "zzz"], buf
end

assert('InputStream#each ""') do
  vec = InputStream.new("")
  buf = []
  vec.each do |line|
    buf << line
  end
  assert_equal [], buf
end

assert('InputStream#rewind') do
  vec = InputStream.new("abcdef")
  assert_equal "ab", vec.read(2)
  assert_equal "cde", vec.read(3)
  vec.rewind
  assert_equal "abcd", vec.read(4)
  assert_equal "ef", vec.read(5)
end

