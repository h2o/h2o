##
# IO Test

assert('File', '15.2.21') do
  File.class == Class
end

assert('File', '15.2.21.2') do
  File.superclass == IO
end

assert('File TEST SETUP') do
  MRubyIOTestUtil.io_test_setup
end

assert('File#initialize', '15.2.21.4.1') do
  io = File.open($mrbtest_io_rfname, "r")
  assert_nil io.close
  assert_raise IOError do
    io.close
  end
end

assert('File#path', '15.2.21.4.2') do
  io = File.open($mrbtest_io_rfname, "r")
  assert_equal $mrbtest_io_msg, io.read
  assert_equal $mrbtest_io_rfname, io.path
  io.close
  assert_equal $mrbtest_io_rfname, io.path
  io.closed?
end

assert('File.basename') do
  assert_equal '/', File.basename('//')
  assert_equal 'a', File.basename('/a/')
  assert_equal 'b', File.basename('/a/b')
  assert_equal 'b', File.basename('../a/b')
end

assert('File.dirname') do
  assert_equal '.',    File.dirname('')
  assert_equal '.',    File.dirname('a')
  assert_equal '/',    File.dirname('/a')
  assert_equal 'a',    File.dirname('a/b')
  assert_equal '/a',   File.dirname('/a/b')
end

assert('File.extname') do
  assert_equal '.txt', File.extname('foo/foo.txt')
  assert_equal '.gz',  File.extname('foo/foo.tar.gz')
  assert_equal '', File.extname('foo/bar')
  assert_equal '', File.extname('foo/.bar')
  assert_equal '', File.extname('foo.txt/bar')
  assert_equal '', File.extname('.foo')
end

assert('IO#flock') do
  f = File.open $mrbtest_io_rfname
  assert_equal(f.flock(File::LOCK_SH), 0)
  assert_equal(f.flock(File::LOCK_UN), 0)
  assert_equal(f.flock(File::LOCK_EX | File::LOCK_NB), 0)
  assert_equal(f.flock(File::LOCK_UN), 0)
  f.close
  true
end

assert('File.join') do
  File.join() == "" and
  File.join("a") == "a" and
  File.join("/a") == "/a" and
  File.join("a/") == "a/" and
  File.join("a", "b", "c") == "a/b/c" and
  File.join("/a", "b", "c") == "/a/b/c" and
  File.join("a", "b", "c/") == "a/b/c/" and
  File.join("a/", "/b/", "/c") == "a/b/c"
end

assert('File.realpath') do
  usrbin = IO.popen("cd bin; /bin/pwd -P") { |f| f.read.chomp }
  assert_equal usrbin, File.realpath("bin")
end

assert('File TEST CLEANUP') do
  assert_nil MRubyIOTestUtil.io_test_cleanup
end

assert('File.expand_path') do
  assert_equal "/",    File.expand_path("..", "/tmp"),       "parent path with base_dir (1)"
  assert_equal "/tmp", File.expand_path("..", "/tmp/mruby"), "parent path with base_dir (2)"

  assert_equal "/home", File.expand_path("/home"),      "absolute"
  assert_equal "/home", File.expand_path("/home", "."), "absolute with base_dir"

  assert_equal "/hoge", File.expand_path("/tmp/..//hoge")
  assert_equal "/hoge", File.expand_path("////tmp/..///////hoge")

  assert_equal "/", File.expand_path("../../../..", "/")
  assert_equal "/", File.expand_path(([".."] * 100).join("/"))
end

assert('File.expand_path (with ENV)') do
  skip unless Object.const_defined?(:ENV) && ENV['HOME']

  assert_equal ENV['HOME'], File.expand_path("~/"),      "home"
  assert_equal ENV['HOME'], File.expand_path("~/", "/"), "home with base_dir"

  assert_equal "#{ENV['HOME']}/user", File.expand_path("user", ENV['HOME']), "relative with base_dir"
end
