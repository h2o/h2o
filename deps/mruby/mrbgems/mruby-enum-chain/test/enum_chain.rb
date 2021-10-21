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

assert("Enumerable#+") do
  a = [].each
  b = {}.reverse_each
  c = Object.new # not has #each method

  assert_kind_of Enumerator::Chain, a + b
  assert_kind_of Enumerator::Chain, a + c
  assert_kind_of Enumerator::Chain, b + a
  assert_kind_of Enumerator::Chain, b + c
  assert_raise(NoMethodError) { c + a }
end

assert("Enumerator.new") do
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

  aa = a.chain(a.reverse_each)
  assert_kind_of Enumerator, aa.each
  assert_equal [1, 2, 3, 3, 2, 1], aa.each.to_a

  aa = a.chain(a.reverse_each, a)
  assert_kind_of Enumerator, aa.each
  assert_equal [1, 2, 3, 3, 2, 1, 1, 2, 3], aa.each.to_a

  aa = a.chain(Object.new)
  assert_kind_of Enumerator, aa.each
  assert_raise(NoMethodError) {  aa.each.to_a }
end

assert("Enumerator::Chain#size") do
  a = [1, 2, 3]

  aa = a.chain(a)
  assert_equal 6, aa.size

  aa = a.chain(a.reverse_each)
  assert_nil aa.size

  aa = a.chain(a.reverse_each, a)
  assert_nil aa.size

  aa = a.chain(Object.new)
  assert_nil aa.size
end
