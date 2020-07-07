unless SocketTest.win?

assert('Socket.gethostname') do
  assert_true(Socket.gethostname.is_a? String)
end

assert('Socket::getaddrinfo') do
  ret = Socket.getaddrinfo("localhost", 53, Socket::AF_INET, Socket::SOCK_DGRAM)
  assert_true ret.size >= 1
  a = ret[0]
  assert_equal "AF_INET",           a[0]
  assert_equal 53,                  a[1]
  # documents says it's a hostname but CRuby returns an address
  #assert_equal "127.0.0.1",         a[2]
  assert_equal "127.0.0.1",         a[3]
  assert_equal Socket::AF_INET,     a[4]
  assert_equal Socket::SOCK_DGRAM,  a[5]
  assert_equal Socket::IPPROTO_UDP, a[6] unless SocketTest.cygwin?
end

assert('Socket#recvfrom') do
  begin
    sstr = "abcdefg"
    s = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
    c = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
    s.bind(Socket.sockaddr_in(0, "127.0.0.1"))
    c.send sstr, 0, s.getsockname
    rstr, ai = s.recvfrom sstr.size

    assert_equal sstr, rstr
    assert_equal "127.0.0.1", ai.ip_address
  ensure
    s.close rescue nil
    c.close rescue nil
  end
end

end   # win?
