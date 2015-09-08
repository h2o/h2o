assert('Dir') do
  assert_equal(Class, Dir.class)
end

assert('DirTest.setup') do
  DirTest.setup
end

assert('Dir.chdir') do
  assert_equal 0, Dir.chdir(DirTest.sandbox)
end

assert('Dir.entries') do
  a = Dir.entries(DirTest.sandbox)
  assert_true a.include? "a"
  assert_true a.include? "b"
end

assert('Dir.exist?') do
  assert_true Dir.exist?(DirTest.sandbox)
  assert_false Dir.exist?(DirTest.sandbox + "/nosuchdir")
end

assert('Dir.foreach') do
  a = []
  Dir.foreach(DirTest.sandbox) { |s| a << s }
  assert_true a.include? "a"
  assert_true a.include? "b"
end

assert('Dir.getwd') do
  s = Dir.getwd
  assert_true s.kind_of? String
end

assert('Dir.mkdir') do
  m1 = DirTest.sandbox + "/mkdir1"
  m2 = DirTest.sandbox + "/mkdir2"
  assert_equal 0, Dir.mkdir(m1)
  assert_equal 0, Dir.mkdir(m2, 0765)
end

assert('Dir.delete') do
  s = DirTest.sandbox + "/delete"
  Dir.mkdir(s)
  assert_true Dir.exist?(s)

  Dir.delete(s)
  assert_false Dir.exist?(s)
end

assert('Dir.open') do
  a = []
  Dir.open(DirTest.sandbox) { |d|
    d.each { |s| a << s }
  }
  assert_true a.include? "a"
  assert_true a.include? "b"
end

assert('Dir#initialize and Dir#close') do
  d = Dir.new(".")
  assert_true d.instance_of? Dir
  assert_nil d.close
end

assert('Dir#close') do
  d = Dir.new(".")
end

assert('Dir#each') do
  a = []
  d = Dir.open(DirTest.sandbox)
  d.each { |s| a << s }
  d.close
  assert_true a.include? "a"
  assert_true a.include? "b"
end

assert('Dir#read') do
  a = []
  d = Dir.open(DirTest.sandbox)
  while s = d.read
    a << s
  end
  d.close
  assert_true a.include? "a"
  assert_true a.include? "b"
end

assert('Dir#rewind') do
  d = Dir.open(DirTest.sandbox)
  while d.read; end

  assert_equal d, d.rewind

  a = []
  while s = d.read
    a << s
  end
  d.close
  assert_true a.include? "a"
  assert_true a.include? "b"
end

# Note: behaviors of seekdir(3) and telldir(3) are so platform-dependent
# that we cannot write portable tests here.

assert('Dir#tell') do
  n = nil
  Dir.open(DirTest.sandbox) { |d|
    n = d.tell
  }
  assert_true n.is_a? Integer
end

assert('Dir#seek') do
  d1 = Dir.open(DirTest.sandbox)
  d1.read
  n = d1.tell
  d1.read
  d2 = d1.seek(n)
  assert_equal d1, d2
end

assert('DirTest.teardown') do
  DirTest.teardown
end
