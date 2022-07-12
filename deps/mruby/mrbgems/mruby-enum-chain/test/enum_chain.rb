##
# Enumerator::Chain test

assert("Enumerable#chain") do
  a = []
  b = {}
  c = Object.new # not has #each method

  assert_kind_of Enumerator::Chain, a.chain
  assert_kind_of Enumerator::Chain, a.chain(b)
  assert_kind_of Enumerator::Chain, a.chain(b, c)
  assert_raise(NoMethodError) { c.chain }
end

assert("Enumerator#+") do
  a = [].each
  b = {}.each
  c = Object.new # not has #each method

  assert_kind_of Enumerator::Chain, a + b
  assert_kind_of Enumerator::Chain, a + c
  assert_kind_of Enumerator::Chain, b + a
  assert_kind_of Enumerator::Chain, b + c
  assert_raise(NoMethodError) { c + a }
end

assert("Enumerator::Chain.new") do
  a = []
  b = {}
  c = Object.new # not has #each method

  assert_kind_of Enumerator::Chain, Enumerator::Chain.new
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(a, a)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(a, b)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(a, c)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(b, a)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(b, b)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(b, c)
  assert_kind_of Enumerator::Chain, Enumerator::Chain.new(c, a)
end

assert("Enumerator::Chain#each") do
  a = [1, 2, 3]

  aa = a.chain(a)
  assert_kind_of Enumerator, aa.each
  assert_equal [1, 2, 3, 1, 2, 3], aa.each.to_a

  aa = a.chain(6..9)
  assert_kind_of Enumerator, aa.each
  assert_equal [1, 2, 3, 6, 7, 8, 9], aa.each.to_a

  aa = a.chain((-3..-2).each_with_index, a)
  assert_kind_of Enumerator, aa.each
  assert_equal [1, 2, 3, [-3, 0], [-2, 1], 1, 2, 3], aa.each.to_a

  aa = a.chain(Object.new)
  assert_kind_of Enumerator, aa.each
  assert_raise(NoMethodError) {  aa.each.to_a }
end

assert("Enumerator::Chain#size") do
  a = [1, 2, 3]

  aa = a.chain(a)
  assert_equal 6, aa.size

  aa = a.chain(3..4)
  assert_nil aa.size

  aa = a.chain(3..4, a)
  assert_nil aa.size

  aa = a.chain(Object.new)
  assert_nil aa.size
end

assert("Enumerator::Chain#rewind") do
  rewound = nil
  e1 = [1, 2]
  e2 = (4..6)
  (class << e1; self end).define_method(:rewind) { rewound << self }
  (class << e2; self end).define_method(:rewind) { rewound << self }
  c = e1.chain(e2)

  rewound = []
  c.rewind
  assert_equal [], rewound

  rewound = []
  c.each{break c}.rewind
  assert_equal [e1], rewound

  rewound = []
  c.each{}.rewind
  assert_equal [e2, e1], rewound
end

assert("Enumerator::Chain#+") do
  a = [].chain
  b = {}.chain
  c = Object.new # not has #each method

  assert_kind_of Enumerator::Chain, a + b
  assert_kind_of Enumerator::Chain, a + c
  assert_kind_of Enumerator::Chain, b + a
  assert_kind_of Enumerator::Chain, b + c
end
