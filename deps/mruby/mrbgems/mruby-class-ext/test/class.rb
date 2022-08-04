assert 'Class#subclasses' do
  a = Class.new
  b = Class.new(a)
  c = Class.new(b)
  d = Class.new(a)

  a_sub = a.subclasses
  assert_equal(2, a_sub.size)
  assert_true(a_sub.include?(b))
  assert_true(a_sub.include?(d))
  assert_equal([c], b.subclasses)
  assert_equal([], c.subclasses)
end
