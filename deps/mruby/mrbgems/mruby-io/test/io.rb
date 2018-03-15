##
# IO Test

unless Object.respond_to? :assert_nothing_raised
  def assert_nothing_raised(*exp)
    ret = true
    if $mrbtest_assert
      $mrbtest_assert_idx += 1
      msg = exp.last.class == String ? exp.pop : ""
      begin
        yield
      rescue Exception => e
        msg = "#{msg} exception raised."
        diff = "      Class: <#{e.class}>\n" +
          "    Message: #{e.message}"
        $mrbtest_assert.push([$mrbtest_assert_idx, msg, diff])
        ret = false
      end
    end
    ret
  end
end

assert('IO TEST SETUP') do
  MRubyIOTestUtil.io_test_setup
  $cr = MRubyIOTestUtil.win? ? 1 : 0  # "\n" include CR or not
end

assert('IO', '15.2.20') do
  assert_equal(Class, IO.class)
end

assert('IO', '15.2.20.2') do
  assert_equal(Object, IO.superclass)
end

assert('IO', '15.2.20.3') do
  assert_include(IO.included_modules, Enumerable)
end

assert('IO.open', '15.2.20.4.1') do
  fd = IO.sysopen $mrbtest_io_rfname
  assert_equal Fixnum, fd.class
  io = IO.open fd
  assert_equal IO, io.class
  assert_equal $mrbtest_io_msg, io.read
  io.close

  fd = IO.sysopen $mrbtest_io_rfname
  IO.open(fd) do |io|
    assert_equal $mrbtest_io_msg, io.read
  end

  true
end

assert('IO#close', '15.2.20.5.1') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  assert_nil io.close
end

assert('IO#closed?', '15.2.20.5.2') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  assert_false io.closed?
  io.close
  assert_true io.closed?
end

#assert('IO#each', '15.2.20.5.3') do
#assert('IO#each_byte', '15.2.20.5.4') do
#assert('IO#each_line', '15.2.20.5.5') do

assert('IO#eof?', '15.2.20.5.6') do
  io = IO.new(IO.sysopen($mrbtest_io_wfname, 'w'), 'w')
  assert_raise(IOError) do
    io.eof?
  end
  io.close

  # empty file
  io = IO.open(IO.sysopen($mrbtest_io_wfname, 'w'), 'w')
  io.close
  io = IO.open(IO.sysopen($mrbtest_io_wfname, 'r'), 'r')
  assert_true io.eof?
  io.close

  # nonempty file
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  assert_false io.eof?
  io.readchar
  assert_false io.eof?
  io.read
  assert_true io.eof?
  io.close

  true
end

assert('IO#flush', '15.2.20.5.7') do
  # Note: mruby-io does not have any buffer to be flushed now.
  io = IO.new(IO.sysopen($mrbtest_io_wfname))
  assert_equal io, io.flush
  io.close
  assert_raise(IOError) do
    io.flush
  end
end

assert('IO#getc', '15.2.20.5.8') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  $mrbtest_io_msg.each_char { |ch|
    assert_equal ch, io.getc
  }
  assert_equal nil, io.getc
  io.close
  true
end

#assert('IO#gets', '15.2.20.5.9') do
#assert('IO#initialize_copy', '15.2.20.5.10') do
#assert('IO#print', '15.2.20.5.11') do
#assert('IO#putc', '15.2.20.5.12') do
#assert('IO#puts', '15.2.20.5.13') do

assert('IO#read', '15.2.20.5.14') do
  IO.open(IO.sysopen($mrbtest_io_rfname)) do |io|
    assert_raise(ArgumentError) { io.read(-5) }
    assert_raise(TypeError) { io.read("str") }

    len = $mrbtest_io_msg.length
    assert_equal '', io.read(0)
    assert_equal 'mruby', io.read(5)
    assert_equal $mrbtest_io_msg[5,len], io.read(len)

    assert_equal "", io.read
    assert_nil io.read(1)
  end

  IO.open(IO.sysopen($mrbtest_io_rfname)) do |io|
    assert_equal $mrbtest_io_msg, io.read
  end
end

assert "IO#read(n) with n > IO::BUF_SIZE" do
  skip "pipe is not supported on this platform" if MRubyIOTestUtil.win?
  r,w = IO.pipe
  n = IO::BUF_SIZE+1
  w.write 'a'*n
  assert_equal r.read(n), 'a'*n
end

assert('IO#readchar', '15.2.20.5.15') do
  # almost same as IO#getc
  IO.open(IO.sysopen($mrbtest_io_rfname)) do |io|
    $mrbtest_io_msg.each_char { |ch|
      assert_equal ch, io.readchar
    }
    assert_raise(EOFError) do
      io.readchar
    end
  end
end

#assert('IO#readline', '15.2.20.5.16') do
#assert('IO#readlines', '15.2.20.5.17') do

assert('IO#sync', '15.2.20.5.18') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  s = io.sync
  assert_true(s == true || s == false)
  io.close
  assert_raise(IOError) do
    io.sync
  end
end

assert('IO#sync=', '15.2.20.5.19') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  io.sync = true
  assert_true io.sync
  io.sync = false
  assert_false io.sync
  io.close
  assert_raise(IOError) do
    io.sync = true
  end
end

assert('IO#write', '15.2.20.5.20') do
  io = IO.open(IO.sysopen($mrbtest_io_wfname))
  assert_equal 0, io.write("")
  io.close

  io = IO.open(IO.sysopen($mrbtest_io_wfname, "r+"), "r+")
  assert_equal 7, io.write("abcdefg")
  io.rewind
  assert_equal "ab", io.read(2)
  assert_equal 3, io.write("123")
  io.rewind
  assert_equal "ab123fg", io.read
  io.close

  true
end

assert('IO#<<') do
  io = IO.open(IO.sysopen($mrbtest_io_wfname))
  io << "" << ""
  assert_equal 0, io.pos
  io.close
  true
end

assert('IO#dup for readable') do
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  dup = io.dup
  assert_true io != dup
  assert_true io.fileno != dup.fileno
  assert_equal 'm', dup.sysread(1)
  assert_equal 'r', io.sysread(1)
  assert_equal 'u', dup.sysread(1)
  assert_equal 'b', io.sysread(1)
  assert_equal 'y', dup.sysread(1)
  dup.close
  assert_false io.closed?
  io.close
  true
end

assert('IO#dup for writable') do
  io = IO.open(IO.sysopen($mrbtest_io_wfname, 'w+'), 'w+')
  dup = io.dup
  io.syswrite "mruby"
  assert_equal 5, dup.sysseek(0, IO::SEEK_CUR)
  io.sysseek 0, IO::SEEK_SET
  assert_equal 0, dup.sysseek(0, IO::SEEK_CUR)
  assert_equal "mruby", dup.sysread(5)
  dup.close
  io.close
  true
end

assert('IO.for_fd') do
  fd = IO.sysopen($mrbtest_io_rfname)
  io = IO.for_fd(fd)
    assert_equal $mrbtest_io_msg, io.read
  io.close
  true
end

assert('IO.new') do
  io = IO.new(0)
  io.close
  true
end

assert('IO gc check') do
  100.times { IO.new(0) }
end

assert('IO.sysopen("./nonexistent")') do
  if Object.const_defined? :Errno
    eclass = Errno::ENOENT
  else
    eclass = RuntimeError
  end
  assert_raise eclass do
    fd = IO.sysopen "./nonexistent"
    IO._sysclose fd
  end
end

assert('IO.sysopen, IO#sysread') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd
  str1 = "     "
  str2 = io.sysread(5, str1)
  assert_equal $mrbtest_io_msg[0,5], str1
  assert_equal $mrbtest_io_msg[0,5], str2
  assert_raise EOFError do
    io.sysread(10000)
    io.sysread(10000)
  end

  assert_raise RuntimeError do
    io.sysread(5, "abcde".freeze)
  end

  io.close
  assert_equal "", io.sysread(0)
  assert_raise(IOError) { io.sysread(1) }
  assert_raise(ArgumentError) { io.sysread(-1) }
  io.closed?

  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  assert_raise(IOError) { io.sysread(1) }
  io.close
  true
end

assert('IO.sysopen, IO#syswrite') do
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  str = "abcdefg"
  len = io.syswrite(str)
  assert_equal str.size, len
  io.close

  io = IO.new(IO.sysopen($mrbtest_io_rfname), "r")
  assert_raise(IOError) { io.syswrite("a") }
  io.close

  true
end

assert('IO#_read_buf') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd
  def io._buf
    @buf
  end
  msg_len = $mrbtest_io_msg.size
  assert_equal '', io._buf
  assert_equal $mrbtest_io_msg, io._read_buf
  assert_equal $mrbtest_io_msg, io._buf
  assert_equal 'mruby', io.read(5)
  assert_equal 5, io.pos
  assert_equal msg_len - 5, io._buf.size
  assert_equal $mrbtest_io_msg[5,100], io.read
  assert_equal 0, io._buf.size
  assert_raise EOFError do
    io._read_buf
  end
  assert_equal true, io.eof
  assert_equal true, io.eof?
  io.close
  io.closed?
end

assert('IO#isatty') do
  skip "isatty is not supported on this platform" if MRubyIOTestUtil.win?
  f1 = File.open("/dev/tty")
  f2 = File.open($mrbtest_io_rfname)

  assert_true  f1.isatty
  assert_false f2.isatty

  f1.close
  f2.close
  true
end

assert('IO#pos=, IO#seek') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd
  def io._buf
    @buf
  end
  assert_equal 'm', io.getc
  assert_equal 1, io.pos
  assert_equal 0, io.seek(0)
  assert_equal 0, io.pos
  io.close
  io.closed?
end

assert('IO#rewind') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd
  assert_equal 'm', io.getc
  assert_equal 1, io.pos
  assert_equal 0, io.rewind
  assert_equal 0, io.pos
  io.close
  io.closed?
end

assert('IO#gets') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd

  # gets without arguments
  assert_equal $mrbtest_io_msg, io.gets, "gets without arguments"
  assert_equal nil, io.gets, "gets returns nil, when EOF"

  # gets with limit
  io.pos = 0
  assert_equal $mrbtest_io_msg[0, 5], io.gets(5), "gets with limit"

  # gets with rs
  io.pos = 0
  assert_equal $mrbtest_io_msg[0, 6], io.gets(' '), "gets with rs"

  # gets with rs, limit
  io.pos = 0
  assert_equal $mrbtest_io_msg[0, 5], io.gets(' ', 5), "gets with rs, limit"
  io.close
  assert_equal true, io.closed?, "close success"

  # reading many-lines file.
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  io.write "0123456789" * 2 + "\na"
  assert_equal 22 + $cr, io.pos
  io.close
  assert_equal true, io.closed?

  fd = IO.sysopen $mrbtest_io_wfname
  io = IO.new fd
  line = io.gets

  # gets first line
  assert_equal "0123456789" * 2 + "\n", line, "gets first line"
  assert_equal 21, line.size
  assert_equal 21 + $cr, io.pos

  # gets second line
  assert_equal "a", io.gets, "gets second line"

  # gets third line
  assert_equal nil, io.gets, "gets third line; returns nil"

  io.close
  io.closed?
end

assert('IO#gets - paragraph mode') do
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  io.write "0" * 10 + "\n"
  io.write "1" * 10 + "\n\n"
  io.write "2" * 10 + "\n"
  assert_equal 34 + $cr * 4, io.pos
  io.close
  assert_equal true, io.closed?

  fd = IO.sysopen $mrbtest_io_wfname
  io = IO.new fd
  para1 = "#{'0' * 10}\n#{'1' * 10}\n\n"
  text1 = io.gets("")
  assert_equal para1, text1
  para2 = "#{'2' * 10}\n"
  text2 = io.gets("")
  assert_equal para2, text2
  io.close
  io.closed?
end

assert('IO.popen') do
  begin
    $? = nil
    io = IO.popen("echo mruby-io")
    assert_true io.close_on_exec?
    assert_equal Fixnum, io.pid.class

    out = io.read
    assert_equal out.class, String
    assert_include out, 'mruby-io'

    io.close
    if Object.const_defined? :Process
      assert_true $?.success?
    else
      assert_equal 0, $?
    end

    assert_true io.closed?
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('IO.popen with in option') do
  begin
    IO.pipe do |r, w|
      w.write 'hello'
      w.close
      assert_equal "hello", IO.popen("cat", "r", in: r) { |i| i.read }
      assert_equal "", r.read
    end
    assert_raise(ArgumentError) { IO.popen("hello", "r", in: Object.new) }
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('IO.popen with out option') do
  begin
    IO.pipe do |r, w|
      IO.popen("echo 'hello'", "w", out: w) {}
      w.close
      assert_equal "hello\n", r.read
    end
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('IO.popen with err option') do
  begin
    IO.pipe do |r, w|
      assert_equal "", IO.popen("echo 'hello' 1>&2", "r", err: w) { |i| i.read }
      w.close
      assert_equal "hello\n", r.read
    end
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('IO.read') do
  # empty file
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  io.close
  assert_equal "",  IO.read($mrbtest_io_wfname)
  assert_equal nil, IO.read($mrbtest_io_wfname, 1)

  # one byte file
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  io.write "123"
  io.close
  assert_equal "123", IO.read($mrbtest_io_wfname)
  assert_equal "",    IO.read($mrbtest_io_wfname, 0)
  assert_equal "1",   IO.read($mrbtest_io_wfname, 1)
  assert_equal "",    IO.read($mrbtest_io_wfname, 0, 10)
  assert_equal "23",  IO.read($mrbtest_io_wfname, 2, 1)
  assert_equal "23",  IO.read($mrbtest_io_wfname, 10, 1)
  assert_equal "",    IO.read($mrbtest_io_wfname, nil, 10)
  assert_equal nil,   IO.read($mrbtest_io_wfname, 1, 10)
end

assert('IO#fileno') do
  fd = IO.sysopen $mrbtest_io_rfname
  io = IO.new fd
  assert_equal io.fileno, fd
  assert_equal io.to_i, fd
  io.close
  io.closed?
end

assert('IO#close_on_exec') do
  fd = IO.sysopen $mrbtest_io_wfname, "w"
  io = IO.new fd, "w"
  begin
    # IO.sysopen opens a file descripter with O_CLOEXEC flag.
    assert_true io.close_on_exec?
  rescue ScriptError
    io.close
    skip "IO\#close_on_exec is not implemented."
  end

  io.close_on_exec = false
  assert_equal(false, io.close_on_exec?)
  io.close_on_exec = true
  assert_equal(true, io.close_on_exec?)
  io.close_on_exec = false
  assert_equal(false, io.close_on_exec?)

  io.close
  io.closed?

  begin
    r, w = IO.pipe
    assert_equal(true, r.close_on_exec?)
    r.close_on_exec = false
    assert_equal(false, r.close_on_exec?)
    r.close_on_exec = true
    assert_equal(true, r.close_on_exec?)

    assert_equal(true, w.close_on_exec?)
    w.close_on_exec = false
    assert_equal(false, w.close_on_exec?)
    w.close_on_exec = true
    assert_equal(true, w.close_on_exec?)
  ensure
    r.close unless r.closed?
    w.close unless w.closed?
  end
end

assert('IO#sysseek') do
  IO.open(IO.sysopen($mrbtest_io_rfname)) do |io|
    assert_equal 2, io.sysseek(2)
    assert_equal 5, io.sysseek(3, IO::SEEK_CUR) # 2 + 3 => 5
    assert_equal $mrbtest_io_msg.size - 4, io.sysseek(-4, IO::SEEK_END)
  end
end

assert('IO.pipe') do
  begin
    called = false
    IO.pipe do |r, w|
      assert_true r.kind_of?(IO)
      assert_true w.kind_of?(IO)
      assert_false r.closed?
      assert_false w.closed?
      assert_true FileTest.pipe?(r)
      assert_true FileTest.pipe?(w)
      assert_nil r.pid
      assert_nil w.pid
      assert_true 2 < r.fileno
      assert_true 2 < w.fileno
      assert_true r.fileno != w.fileno
      assert_false r.sync
      assert_true w.sync
      assert_equal 8, w.write('test for')
      assert_equal 'test', r.read(4)
      assert_equal ' for', r.read(4)
      assert_equal 5, w.write(' pipe')
      assert_equal nil, w.close
      assert_equal ' pipe', r.read
      called = true
      assert_raise(IOError) { r.write 'test' }
      # TODO:
      # This assert expect raise IOError but got RuntimeError
      # Because mruby-io not have flag for I/O readable
      # assert_raise(IOError) { w.read }
    end
    assert_true called

    assert_nothing_raised do
      IO.pipe { |r, w| r.close; w.close }
    end
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('`cmd`') do
  begin
    assert_equal `echo foo`, "foo\n"
  rescue NotImplementedError => e
    skip e.message
  end
end

assert('IO TEST CLEANUP') do
  assert_nil MRubyIOTestUtil.io_test_cleanup
end
