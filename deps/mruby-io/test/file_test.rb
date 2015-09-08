##
# FileTest

assert('FileTest TEST SETUP') do
  MRubyIOTestUtil.io_test_setup
end

assert("FileTest.directory?") do
  assert_equal true,  FileTest.directory?("/tmp")
  assert_equal false, FileTest.directory?("/bin/sh")
end

assert("FileTest.exist?") do
  assert_equal true,  FileTest.exist?($mrbtest_io_rfname), "filename - exist"
  assert_equal false, FileTest.exist?($mrbtest_io_rfname + "-"), "filename - not exist"
  io = IO.new(IO.sysopen($mrbtest_io_rfname))
  assert_equal true,  FileTest.exist?(io), "io obj - exist"
  io.close
  assert_equal true, io.closed?
  assert_raise IOError do
    FileTest.exist?(io)
  end
end

assert("FileTest.file?") do
  assert_equal false, FileTest.file?("/tmp")
  assert_equal true,  FileTest.file?("/bin/sh")
end

assert("FileTest.pipe?") do
  io = IO.popen("ls")
  assert_equal true,  FileTest.pipe?(io)
  assert_equal false, FileTest.pipe?("/tmp")
end

assert('FileTest.size') do
  assert_equal FileTest.size($mrbtest_io_rfname), $mrbtest_io_msg.size
  assert_equal FileTest.size($mrbtest_io_wfname), 0
end

assert("FileTest.size?") do
  assert_equal $mrbtest_io_msg.size, FileTest.size?($mrbtest_io_rfname)
  assert_equal nil, FileTest.size?($mrbtest_io_wfname)
  assert_equal nil, FileTest.size?("not-exist-test-target-file")

  fp1 = File.open($mrbtest_io_rfname)
  fp2 = File.open($mrbtest_io_wfname)
  assert_equal $mrbtest_io_msg.size,  FileTest.size?(fp1)
  assert_equal nil, FileTest.size?(fp2)
  fp1.close
  fp2.close

  assert_raise IOError do
    FileTest.size?(fp1)
  end
  assert_raise IOError do
    FileTest.size?(fp2)
  end

  fp1.closed? && fp2.closed?
end

assert("FileTest.socket?") do
  assert_true FileTest.socket?($mrbtest_io_socketname)
end

assert("FileTest.symlink?") do
  assert_true FileTest.symlink?($mrbtest_io_symlinkname)
end

assert("FileTest.zero?") do
  assert_equal false, FileTest.zero?($mrbtest_io_rfname)
  assert_equal true,  FileTest.zero?($mrbtest_io_wfname)
  assert_equal false, FileTest.zero?("not-exist-test-target-file")

  fp1 = File.open($mrbtest_io_rfname)
  fp2 = File.open($mrbtest_io_wfname)
  assert_equal false, FileTest.zero?(fp1)
  assert_equal true,  FileTest.zero?(fp2)
  fp1.close
  fp2.close

  assert_raise IOError do
    FileTest.zero?(fp1)
  end
  assert_raise IOError do
    FileTest.zero?(fp2)
  end

  fp1.closed? && fp2.closed?
end

assert('FileTest TEST CLEANUP') do
  assert_nil MRubyIOTestUtil.io_test_cleanup
end
