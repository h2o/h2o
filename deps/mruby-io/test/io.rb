##
# IO Test

assert('IO TEST SETUP') do
  MRubyIOTestUtil.io_test_setup
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
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  $mrbtest_io_msg.each_char { |ch|
    # XXX
    #assert_false io.eof?
    io.getc
  }
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
  io.close
  io.closed?
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
  assert_equal 22, io.pos
  io.close
  assert_equal true, io.closed?

  fd = IO.sysopen $mrbtest_io_wfname
  io = IO.new fd
  line = io.gets

  # gets first line
  assert_equal "0123456789" * 2 + "\n", line, "gets first line"
  assert_equal 21, line.size
  assert_equal 21, io.pos

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
  assert_equal 34, io.pos
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
  io = IO.popen("ls")
  assert_true io.close_on_exec?
  assert_equal Fixnum, io.pid.class
  ls = io.read
  assert_equal ls.class, String
  assert_include ls, 'AUTHORS'
  assert_include ls, 'mrblib'
  io.close
  io.closed?
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

  # # Use below when IO.pipe is implemented.
  # begin
  #   r, w = IO.pipe
  #   assert_equal(false, r.close_on_exec?)
  #   r.close_on_exec = true
  #   assert_equal(true, r.close_on_exec?)
  #   r.close_on_exec = false
  #   assert_equal(false, r.close_on_exec?)
  #   r.close_on_exec = true
  #   assert_equal(true, r.close_on_exec?)

  #   assert_equal(false, w.close_on_exec?)
  #   w.close_on_exec = true
  #   assert_equal(true, w.close_on_exec?)
  #   w.close_on_exec = false
  #   assert_equal(false, w.close_on_exec?)
  #   w.close_on_exec = true
  #   assert_equal(true, w.close_on_exec?)
  # ensure
  #   r.close unless r.closed?
  #   w.close unless w.closed?
  # end
end

assert('`cmd`') do
  assert_equal `echo foo`, "foo\n"
end

assert('IO TEST CLEANUP') do
  assert_nil MRubyIOTestUtil.io_test_cleanup
end
