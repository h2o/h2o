assert('BasicSocket') do
  assert_equal(Class, BasicSocket.class)
end

assert('super class of BasicSocket') do
  assert_equal(IO, BasicSocket.superclass)
end

assert('BasicSocket.do_not_reverse_lookup') do
  assert_equal(BasicSocket.do_not_reverse_lookup, true)
end

assert('BasicSocket.do_not_reverse_lookup=') do
  BasicSocket.do_not_reverse_lookup = false
  assert_equal(BasicSocket.do_not_reverse_lookup, false)
  BasicSocket.do_not_reverse_lookup = true
end
