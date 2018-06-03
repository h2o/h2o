assert('UDPSocket.new') do
  s = UDPSocket.new
  assert_true(s.is_a? UDPSocket)
  s.close
  s = UDPSocket.new(Socket::AF_INET6)
  assert_true(s.is_a? UDPSocket)
  s.close
  true
end

#assert('UDPSocket#connect') do
#assert('UDPSocket#send') do
#assert('UDPSocket#recv') do

#assert('UDPSocket#bind') do
#assert('UDPSocket#recvfrom_nonblock') do
