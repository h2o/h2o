assert('Addrinfo') do
  assert_equal(Class, Addrinfo.class)
end

assert('super class of Addrinfo') do
  assert_equal(Object, Addrinfo.superclass)
end

assert('Addrinfo.getaddrinfo') do
  ary = Addrinfo.getaddrinfo("localhost", "domain", Socket::AF_INET, Socket::SOCK_STREAM)
  assert_true(ary.size >= 1)
  ai = ary[0]
  assert_equal(ai.afamily, Socket::AF_INET)
  assert_equal(ai.pfamily, Socket::PF_INET)
  assert_equal(ai.socktype, Socket::SOCK_STREAM)
  assert_equal(ai.ip_address, '127.0.0.1')
  assert_equal(ai.ip_port, 53)
end

assert('Addrinfo.foreach') do
  # assume Addrinfo.getaddrinfo works well
  a = Addrinfo.getaddrinfo("localhost", "domain")
  b = []
  Addrinfo.foreach("localhost", "domain") { |ai| b << ai }
  assert_equal(a.size, b.size)
end

assert('Addrinfo.ip') do
  ai = Addrinfo.ip('127.0.0.1')
  assert_equal('127.0.0.1', ai.ip_address)
  assert_equal(Socket::AF_INET, ai.afamily)
  assert_equal(0, ai.ip_port)
  assert_equal(0, ai.socktype)
  assert_equal(0, ai.protocol)
end

assert('Addrinfo.tcp') do
  ai = Addrinfo.tcp('127.0.0.1', 'smtp')
  assert_equal('127.0.0.1', ai.ip_address)
  assert_equal(Socket::AF_INET, ai.afamily)
  assert_equal(25, ai.ip_port)
  assert_equal(Socket::SOCK_STREAM, ai.socktype)
  assert_equal(Socket::IPPROTO_TCP, ai.protocol)
end

assert('Addrinfo.udp') do
  ai = Addrinfo.udp('127.0.0.1', 'domain')
  assert_equal('127.0.0.1', ai.ip_address)
  assert_equal(Socket::AF_INET, ai.afamily)
  assert_equal(53, ai.ip_port)
  assert_equal(Socket::SOCK_DGRAM, ai.socktype)
  assert_equal(Socket::IPPROTO_UDP, ai.protocol)
end

assert('Addrinfo.unix') do
  skip "unix is not supported on Windows" if SocketTest.win?
  a1 = Addrinfo.unix('/tmp/sock')
  assert_true(a1.unix?)
  assert_equal('/tmp/sock', a1.unix_path)
  assert_equal(Socket::SOCK_STREAM, a1.socktype)
  a2 = Addrinfo.unix('/tmp/sock', Socket::SOCK_DGRAM)
  assert_equal(Socket::SOCK_DGRAM, a2.socktype)
end

assert('Addrinfo#afamily') do
  skip "afamily is not supported on Windows" if SocketTest.win?
  ai4 = Addrinfo.new(Socket.sockaddr_in(1, '127.0.0.1'))
  ai6 = Addrinfo.new(Socket.sockaddr_in(1, '::1'))
  aiu = Addrinfo.new(Socket.sockaddr_un('/tmp/sock'))
  assert_equal(Socket::AF_INET, ai4.afamily)
  assert_equal(Socket::AF_INET6, ai6.afamily)
  assert_equal(Socket::AF_UNIX, aiu.afamily)
end

# assert('Addrinfo#canonname') do

# #getnameinfo
# assert('Addrinfo#inspect') do
# assert('Addrinfo#inspect_socket') do
# assert('Addrinfo#ip?') do
# assert('Addrinfo#ip_address') do
# assert('Addrinfo#ip_port') do
# assert('Addrinfo#ip_unpack') do
# assert('Addrinfo#ipv4?') do
# assert('Addrinfo#ipv6?') do
# assert('Addrinfo#pfamily') do
# assert('Addrinfo#protocol') do
# assert('Addrinfo#socktype') do
# assert('Addrinfo#to_sockaddr') do
# assert('Addrinfo#unix?') do
# #unix_path
