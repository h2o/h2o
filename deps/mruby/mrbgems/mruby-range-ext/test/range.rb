##
# Range(Ext) Test

assert('Range#cover?') do
  assert_true ("a".."z").cover?("c")
  assert_true !("a".."z").cover?("5")
  assert_true ("a".."z").cover?("cc")
  assert_true ("a"..).cover?("c")
  assert_false ("a"..).cover?("5")
  assert_true ("a"..).cover?("cc")
end

assert('Range#first') do
  assert_equal 10, (10..20).first
  assert_equal [10, 11, 12], (10..20).first(3)
  assert_equal 10, (10..).first
  assert_equal [10, 11, 12], (10..).first(3)
  assert_raise(RangeError) { (..1).first }

  skip unless Object.const_defined?(:Float)
  assert_equal [0, 1, 2], (0..Float::INFINITY).first(3)
end

assert('Range#last') do
  assert_equal 20, (10..20).last
  assert_equal 20, (10...20).last
  assert_raise(RangeError) { (10..).last }
  assert_raise(RangeError) { (10...).last }
  assert_equal [18, 19, 20], (10..20).last(3)
  assert_equal [17, 18, 19], (10...20).last(3)
end

assert('Range#size') do
  assert_equal 42, (1..42).size
  assert_equal 41, (1...42).size
  assert_nil ('a'..'z').size
  assert_nil ('a'..).size

  assert_nil (1..).size unless Object.const_defined?(:Float)

  skip unless Object.const_defined?(:Float)
  assert_equal 6, (1...6.3).size
  assert_equal 5, (1...6.0).size
  assert_equal 5, (1.1...6).size
  assert_equal 15, (1.0..15.9).size
  assert_equal Float::INFINITY, (0..Float::INFINITY).size

  assert_equal Float::INFINITY, (1..).size
  assert_equal Float::INFINITY, (1...).size
  assert_equal Float::INFINITY, (1.0..).size
end

assert('Range#max') do
  # returns the maximum value in the range when called with no arguments
  assert_equal 10, (1..10).max
  assert_equal 9, (1...10).max
  assert_equal 536870911, (0...2**29).max

  # returns nil when the endpoint is less than the start point
  assert_equal nil, (100..10).max

  # returns nil when the endpoint equals the start point and the range is exclusive
  assert_equal nil, (5...5).max

  # returns the endpoint when the endpoint equals the start point and the range is inclusive
  assert_equal 5, (5..5).max

  # raises RangeError when called on an endless range
  assert_raise(RangeError) { (10..).max }
  assert_raise(RangeError) { (10...).max }

  skip unless Object.const_defined?(:Float)

  # returns the maximum value in the Float range when called with no arguments
  assert_equal 908.1111, (303.20..908.1111).max

  # raises TypeError when called on an exclusive range and a non Integer value
  assert_raise(TypeError) { (303.20...908.1111).max }

  # returns nil when the endpoint is less than the start point in a Float range
  assert_equal nil, (3003.20..908.1111).max
end

assert('Range#max given a block') do
  # passes each pair of values in the range to the block
  acc = []
  (1..10).max do |a, b|
    acc << a
    acc << b
    a
  end
  (1..10).each do |value|
    assert_true acc.include?(value)
  end

  # passes each pair of elements to the block in reversed order
  acc = []
  (1..5).max do |a, b|
    acc << [a, b]
    a
  end
  assert_equal [[2, 1], [3, 2], [4, 3], [5, 4]], acc

  # returns the element the block determines to be the maximum
  assert_equal 1, ((1..3).max { |_a, _b| -3 })

  # returns nil when the endpoint is less than the start point
  assert_equal nil, ((100..10).max { |x, y| x <=> y })
  assert_equal nil, ((5...5).max { |x, y| x <=> y })
end

assert('Range#min') do
  # returns the minimum value in the range when called with no arguments
  assert_equal 1, (1..10).min
  assert_equal 1, (1...10).min
  assert_equal 1, (1..).min

  # returns nil when the start point is greater than the endpoint
  assert_equal nil, (100..10).min

  # returns nil when the endpoint equals the start point and the range is exclusive
  assert_equal nil, (5...5).min

  # returns the endpoint when the endpoint equals the start point and the range is inclusive
  assert_equal 5, (5..5).min

  skip unless Object.const_defined?(:Float)

  # returns the minimum value in the Float range when called with no arguments
  assert_equal 303.20, (303.20..908.1111).min
  assert_equal 1, (1.0..).min

  # returns nil when the start point is greater than the endpoint in a Float range
  assert_equal nil, (3003.20..908.1111).min
end

assert('Range#min given a block') do
  # raise when called with a block in endless range
  assert_raise(RangeError) { (1..).min{} }

  # passes each pair of values in the range to the block
  acc = []
  (1..10).min do |a, b|
    acc << a
    acc << b
    a
  end
  (1..10).each do |value|
    assert_true acc.include?(value)
  end

  # passes each pair of elements to the block in reversed order
  acc = []
  (1..5).min do |a, b|
    acc << [a, b]
    a
  end
  assert_equal [[2, 1], [3, 1], [4, 1], [5, 1]], acc

  # returns the element the block determines to be the minimum
  assert_equal 3, ((1..3).min { |_a, _b| -3 })

  # returns nil when the start point is greater than the endpoint
  assert_equal nil, ((100..10).min { |x, y| x <=> y })
  assert_equal nil, ((5...5).min { |x, y| x <=> y })
end
