assert('Range#max') do
  # returns the maximum value in the range when called with no arguments
  assert_equal 'l', ('f'..'l').max
  assert_equal 'e', ('a'...'f').max

  # returns nil when the endpoint is less than the start point
  assert_equal nil, ('z'..'l').max
end

assert('Range#max given a block') do
  # returns nil when the endpoint is less than the start point
  assert_equal nil, (('z'..'l').max { |x, y| x <=> y })
end

assert('Range#min') do
  # returns the minimum value in the range when called with no arguments
  assert_equal 'f', ('f'..'l').min

  # returns nil when the start point is greater than the endpoint
  assert_equal nil, ('z'..'l').min
end

assert('Range#min given a block') do
  # returns nil when the start point is greater than the endpoint
  assert_equal nil, (('z'..'l').min { |x, y| x <=> y })
end
