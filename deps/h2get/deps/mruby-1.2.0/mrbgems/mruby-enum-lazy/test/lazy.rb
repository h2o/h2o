assert("Enumerable::Lazy") do
  a = [1, 2]
  assert_equal Enumerable::Lazy, a.lazy.class
end

assert("Enumerable::Lazy laziness") do
  a = Object.new
  def a.each
    return to_enum :each unless block_given?
    self.b << 10
    yield 1
    self.b << 20
    yield 2
    self.b << 30
    yield 3
    self.b << 40
    yield 4
    self.b << 50
    yield 5
  end
  def a.b(b=nil)
    @b = b if b
    @b
  end

  a.b([])
  assert_equal [1,2], a.each.lazy.take(2).force
  assert_equal [10,20], a.b

  a.b([])
  assert_equal [2,4], a.each.lazy.select{|x|x%2==0}.take(2).force
  assert_equal [10,20,30,40], a.b

  a.b([])
  assert_equal [1], a.each.lazy.take_while{|x|x<2}.take(1).force
  assert_equal [10], a.b

  a.b([])
  assert_equal [1], a.each.lazy.take_while{|x|x<2}.take(4).force
  assert_equal [10,20], a.b
end

assert("Enumerable::Lazy#zip with cycle") do
  e1 = [1, 2, 3].cycle
  e2 = [:a, :b].cycle
  assert_equal [[1,:a],[2,:b],[3,:a]], e1.lazy.zip(e2).first(3)
end
