unless SocketTest.win? || SocketTest.cygwin?

def unixserver_test_block
  path = SocketTest.tmppath
  File.unlink path rescue nil
  begin
    result = yield path
  ensure
    File.unlink path rescue nil
  end
  result
end

def with_unix_server
  unixserver_test_block do |path|
    UNIXServer.open(path) { |server|
      yield path, server
    }
  end
end

def with_unix_client
  with_unix_server do |path, server|
    UNIXSocket.open(path) do |csock|
      ssock = server.accept
      begin
        yield path, server, ssock, csock
      ensure
        ssock.close unless ssock.closed? rescue nil
      end
    end
  end
end

assert('UNIXServer.new') do
  unixserver_test_block do |path|
    server = UNIXServer.new(path)
    assert_true server.is_a? UNIXServer
    server.close
    File.unlink path

    s2 = nil
    result = UNIXServer.open(path) { |s1|
      assert_true s1.is_a? UNIXServer
      s2 = s1
      1234
    }
    assert_equal 1234, result
    assert_true s2.is_a? UNIXServer
    assert_true s2.closed?
  end
end

# assert('UNIXServer#accept_nonblock') - would block if fails

assert('UNIXServer#addr') do
  with_unix_server do |path, server|
    assert_equal [ "AF_UNIX", path], server.addr
  end
end

assert('UNIXServer#path') do
  with_unix_server do |path, server|
    assert_equal path, server.path
  end
end

# assert('UNIXServer#peeraddr') - will raise a runtime exception

assert('UNIXServer#listen') do
  with_unix_server do |path, server|
    assert_equal 0, server.listen(1)
  end
end

assert('UNIXServer#sysaccept') do
  with_unix_server do |path, server|
    UNIXSocket.open(path) do |csock|
      begin
        fd = server.sysaccept
        assert_true fd.kind_of? Integer
      ensure
        IO._sysclose(fd) rescue nil
      end
    end
  end
end

assert('UNIXSocket.new') do
  with_unix_server do |path, server|
    c = UNIXSocket.new(path)
    assert_true c.is_a? UNIXSocket
    c.close
    true
  end
end

assert('UNIXSocket#addr') do
  with_unix_client do |path, server, ssock, csock|
    assert_equal [ "AF_UNIX", path ], ssock.addr
    assert_equal [ "AF_UNIX", "" ],   csock.addr
  end
end

assert('UNIXSocket#path') do
  with_unix_client do |path, server, ssock, csock|
    assert_equal path, ssock.path
    assert_equal "",   csock.path
  end
end

assert('UNIXSocket#peeraddr') do
  with_unix_client do |path, server, ssock, csock|
    assert_equal [ "AF_UNIX", ""   ], ssock.peeraddr
    assert_equal [ "AF_UNIX", path ], csock.peeraddr
  end
end

assert('UNIXSocket#recvfrom') do
  with_unix_client do |path, server, ssock, csock|
    str = "0123456789"
    ssock.send str, 0
    a = csock.recvfrom(8)
    assert_equal str[0, 8], a[0]
    assert_equal "AF_UNIX", a[1][0]
    # a[1][1] would be "" or something
  end
end

end # SocketTest.win?
