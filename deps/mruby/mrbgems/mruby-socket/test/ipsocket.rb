unless SocketTest.win?

# Note: most of tests below will fail if UDPSocket is broken.

assert('IPSocket.getaddress') do
  l = IPSocket.getaddress("localhost")
  assert_true (l == "127.0.0.1" or l == "::1")
end

assert('IPSocket.addr') do
  localhost = "127.0.0.1"
  s = UDPSocket.new
  s.bind(localhost, 0)
  port = Addrinfo.new(s.getsockname).ip_port

  a = s.addr
  assert_equal "AF_INET", a[0]
  assert_equal port,      a[1]
  assert_equal localhost, a[2]
  assert_equal localhost, a[3]
  s.close
  true
end

assert('IPSocket.peeraddr') do
  localhost = "127.0.0.1"
  server = UDPSocket.new
  server.bind(localhost, 0)
  port = server.local_address.ip_port

  client = UDPSocket.new
  client.connect(localhost, port)

  a = client.peeraddr
  assert_equal "AF_INET", a[0]
  assert_equal port,      a[1]
  assert_equal localhost, a[2]
  assert_equal localhost, a[3]
  client.close
  server.close
  true
end

end # win?
