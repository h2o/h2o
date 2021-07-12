@obj = Object.new
class << @obj
  include Enumerable
  def foo *a
    a.each { |x| yield x }
  end
end

def assert_take(exp, enumerator)
  result = []
  n = exp.size
  enumerator.each do |v|
    result << v
    n -= 1
    break if n == 0
  end if n > 0
  assert_equal exp, result
end

assert 'Enumerator.class' do
  assert_equal Class, Enumerator.class
end

assert 'Enumerator.superclass' do
  assert_equal Object, Enumerator.superclass
end

assert 'Enumerator.new' do
  assert_equal [0,1,2], 3.times.map{|i| i}.sort
  assert_equal [:x,:y,:z], [:x,:y,:z].each.map{|i| i}.sort
  assert_equal [[:x,1],[:y,2]], {x:1, y:2}.each.map{|i| i}.sort
  assert_equal [1,2,3], @obj.to_enum(:foo, 1,2,3).to_a
  assert_take [1,2,3], Enumerator.new { |y| i = 0; loop { y << (i += 1) } }
  assert_raise(ArgumentError) { Enumerator.new }

  # examples
  fib = Enumerator.new do |y|
    a = b = 1
    loop do
      y << a
      a, b = b, a + b
    end
  end
  assert_take [1,1,2,3,5,8,13,21,34,55], fib
end

assert 'Enumerator#initialize_copy' do
  assert_equal [1, 2, 3], @obj.to_enum(:foo, 1, 2, 3).dup.to_a
  e = @obj.to_enum :foo, 1, 2, 3
  assert_nothing_raised { assert_equal(1, e.next) }
  assert_raise(TypeError) { e.dup }

  e = Enumerator.new { |y| i = 0; loop { y << (i += 1) } }.dup
  assert_nothing_raised { assert_equal(1, e.next) }
  assert_raise(TypeError) { e.dup }
end

assert 'Enumerator#with_index' do
  assert_equal([[1,0],[2,1],[3,2]], @obj.to_enum(:foo, 1, 2, 3).with_index.to_a)
  assert_equal([[1,5],[2,6],[3,7]], @obj.to_enum(:foo, 1, 2, 3).with_index(5).to_a)
  a = []
  @obj.to_enum(:foo, 1, 2, 3).with_index(10).with_index(20) { |*i| a << i }
  assert_equal [[[1, 10], 20], [[2, 11], 21], [[3, 12], 22]], a
end

assert 'Enumerator#with_index string offset' do
  assert_raise(TypeError){ @obj.to_enum(:foo, 1, 2, 3).with_index('1').to_a }
end

assert 'Enumerator#each_with_index' do
  assert_equal([[1,0],[2,1],[3,2]], @obj.to_enum(:foo, 1, 2, 3).each_with_index.to_a)
  a = []
  @obj.to_enum(:foo, 1, 2, 3).each_with_index {|*i| a << i}
  assert_equal([[1, 0], [2, 1], [3, 2]], a)
end

assert 'Enumerator#with_object' do
  obj = [0, 1]
  ret = (1..10).each.with_object(obj) {|i, memo|
    memo[0] += i
    memo[1] *= i
  }
  assert_true(obj.equal?(ret))
  assert_equal([55, 3628800], ret)
end

assert 'Enumerator#with_object arguments' do
  to_three = Enumerator.new do |y|
    3.times do |x|
      y << x
    end
  end

  a = []
  to_three_with_string = to_three.with_object("foo")
  to_three_with_string.each do |x,string|
    a << "#{string}:#{x}"
  end
  assert_equal ["foo:0","foo:1","foo:2"], a
end

assert 'Enumerator#inspect' do
  e = (0..10).each
  assert_equal('#<Enumerator: 0..10:each>', e.inspect)
  e = 'FooObject'.enum_for(:foo, 1)
  assert_equal('#<Enumerator: "FooObject":foo(1)>', e.inspect)
  e = 'FooObject'.enum_for(:foo, 1, 2, 3)
  assert_equal('#<Enumerator: "FooObject":foo(1, 2, 3)>', e.inspect)
  e = nil.enum_for(:to_s)
  assert_equal('#<Enumerator: nil:to_s>', e.inspect)
end

assert 'Enumerator#each' do
  o = Object.new
  def o.each(ary)
    ary << 1
    yield
  end
  ary = []
  e = o.to_enum.each(ary)
  e.next
  assert_equal([1], ary)
end

assert 'Enumerator#each arguments' do
  obj = Object.new

  def obj.each_arg(a, b=:b, *rest)
    yield a
    yield b
    yield rest
    :method_returned
  end

  enum = obj.to_enum :each_arg, :a, :x

  assert_equal [:a, :x, []], enum.each.to_a
  assert_true enum.each.equal?(enum)
  assert_equal :method_returned, enum.each { |elm| elm }

  assert_equal [:a, :x, [:y, :z]], enum.each(:y, :z).to_a
  assert_false enum.each(:y, :z).equal?(enum)
  assert_equal :method_returned, enum.each(:y, :z) { |elm| elm }
end

assert 'Enumerator#next' do
  e = 3.times
  3.times { |i|
    assert_equal i, e.next
  }
  assert_raise(StopIteration) { e.next }
end

assert 'Enumerator#next_values' do
  o = Object.new
  def o.each
    yield
    yield 1
    yield 1, 2
  end
  e = o.to_enum
  assert_equal nil, e.next
  assert_equal 1, e.next
  assert_equal [1,2], e.next
  e = o.to_enum
  assert_equal [], e.next_values
  assert_equal [1], e.next_values
  assert_equal [1,2], e.next_values
end

assert 'Enumerator#peek' do
  a = [1]
  e = a.each
  assert_equal 1, e.peek
  assert_equal 1, e.peek
  assert_equal 1, e.next
  assert_raise(StopIteration) { e.peek }
  assert_raise(StopIteration) { e.peek }
end

assert 'Enumerator#peek modify' do
  o = Object.new
  def o.each
    yield 1,2
  end
  e = o.to_enum
  a = e.peek
  a << 3
  assert_equal([1,2], e.peek)
end

assert 'Enumerator#peek_values' do
  o = Object.new
  def o.each
    yield
    yield 1
    yield 1, 2
  end
  e = o.to_enum
  assert_equal nil, e.peek
  assert_equal nil, e.next
  assert_equal 1, e.peek
  assert_equal 1, e.next
  assert_equal [1,2], e.peek
  assert_equal [1,2], e.next
  e = o.to_enum
  assert_equal [], e.peek_values
  assert_equal [], e.next_values
  assert_equal [1], e.peek_values
  assert_equal [1], e.next_values
  assert_equal [1,2], e.peek_values
  assert_equal [1,2], e.next_values
  e = o.to_enum
  assert_equal [], e.peek_values
  assert_equal nil, e.next
  assert_equal [1], e.peek_values
  assert_equal 1, e.next
  assert_equal [1,2], e.peek_values
  assert_equal [1,2], e.next
  e = o.to_enum
  assert_equal nil, e.peek
  assert_equal [], e.next_values
  assert_equal 1, e.peek
  assert_equal [1], e.next_values
  assert_equal [1,2], e.peek
  assert_equal [1,2], e.next_values
end

assert 'Enumerator#peek_values modify' do
  o = Object.new
  def o.each
    yield 1,2
  end
  e = o.to_enum
  a = e.peek_values
  a << 3
  assert_equal [1,2], e.peek
end

assert 'Enumerator#feed' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum :each, ary
  e.next
  e.feed 1
  e.next
  e.feed 2
  e.next
  e.feed 3
  assert_raise(StopIteration) { e.next }
  assert_equal [1,2,3], ary
end

assert 'Enumerator#feed mixed' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum :each, ary
  e.next
  e.feed 1
  e.next
  e.next
  e.feed 3
  assert_raise(StopIteration) { e.next }
  assert_equal [1,nil,3], ary
end

assert 'Enumerator#feed twice' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum :each, ary
  e.feed 1
  assert_raise(TypeError) { e.feed 2 }
end

assert 'Enumerator#feed before first next' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum :each, ary
  e.feed 1
  e.next
  e.next
  assert_equal [1], ary
end

assert 'Enumerator#feed yielder' do
  x = nil
  e = Enumerator.new {|y| x = y.yield; 10 }
  e.next
  e.feed 100
  assert_raise(StopIteration) { e.next }
  assert_equal 100, x
end

assert 'Enumerator#rewind' do
  e = @obj.to_enum(:foo, 1, 2, 3)
  assert_equal 1, e.next
  assert_equal 2, e.next
  e.rewind
  assert_equal 1, e.next
  assert_equal 2, e.next
  assert_equal 3, e.next
  assert_raise(StopIteration) { e.next }
end

assert 'Enumerator#rewind clear feed' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum(:each, ary)
  e.next
  e.feed 1
  e.next
  e.feed 2
  e.rewind
  e.next
  e.next
  assert_equal([1,nil], ary)
end

assert 'Enumerator#rewind clear' do
  o = Object.new
  def o.each(ary)
    ary << yield
    ary << yield
    ary << yield
  end
  ary = []
  e = o.to_enum :each, ary
  e.next
  e.feed 1
  e.next
  e.feed 2
  e.rewind
  e.next
  e.next
  assert_equal [1,nil], ary
end

assert 'Enumerator::Generator' do
  # note: Enumerator::Generator is a class just for internal
  g = Enumerator::Generator.new {|y| y << 1 << 2 << 3; :foo }
  g2 = g.dup
  a = []
  assert_equal(:foo, g.each {|x| a << x })
  assert_equal([1, 2, 3], a)
  a = []
  assert_equal(:foo, g2.each {|x| a << x })
  assert_equal([1, 2, 3], a)
end

assert 'Enumerator::Generator args' do
  g = Enumerator::Generator.new {|y, x| y << 1 << 2 << 3; x }
  a = []
  assert_equal(:bar, g.each(:bar) {|x| a << x })
  assert_equal([1, 2, 3], a)
end

assert 'Enumerator::Yielder' do
  # note: Enumerator::Yielder is a class just for internal
  a = []
  y = Enumerator::Yielder.new {|x| a << x }
  assert_equal(y, y << 1 << 2 << 3)
  assert_equal([1, 2, 3], a)

  a = []
  y = Enumerator::Yielder.new {|x| a << x }
  assert_equal([1], y.yield(1))
  assert_equal([1, 2], y.yield(2))
  assert_equal([1, 2, 3], y.yield(3))

  assert_raise(LocalJumpError) { Enumerator::Yielder.new }
end

assert 'next after StopIteration' do
  a = [1]
  e = a.each
  assert_equal(1, e.next)
  assert_raise(StopIteration) { e.next }
  assert_raise(StopIteration) { e.next }
  e.rewind
  assert_equal(1, e.next)
  assert_raise(StopIteration) { e.next }
  assert_raise(StopIteration) { e.next }
end

assert 'gc' do
  assert_nothing_raised do
    1.times do
      foo = [1,2,3].to_enum
      GC.start
    end
    GC.start
  end
end

assert 'nested iteration' do
  def (o = Object.new).each
    yield :ok1
    yield [:ok2, :x].each.next
  end
  e = o.to_enum
  assert_equal :ok1, e.next
  assert_equal :ok2, e.next
  assert_raise(StopIteration) { e.next }
end

assert 'Kernel#to_enum' do
  e = nil
  assert_equal Enumerator, [].to_enum.class
  assert_nothing_raised { e = [].to_enum(:_not_implemented_) }
  assert_raise(NoMethodError) { e.first }
end

assert 'modifying existing methods' do
  assert_equal Enumerator, loop.class
  e = 3.times
  i = 0
  loop_ret = loop {
    assert_equal i, e.next
    i += 1
  }
end

assert 'Integral#times' do
  a = 3
  b = a.times
  c = []
  b.with_object(c) do |i, obj|
    obj << i
  end
  assert_equal 3, a
  assert_equal Enumerator, b.class
  assert_equal [0,1,2], c
end

assert 'Enumerable#each_with_index' do
  assert_equal [['a',0],['b',1],['c',2]], ['a','b','c'].each_with_index.to_a
end

assert 'Enumerable#map' do
  a = [1,2,3]
  b = a.map
  c = b.with_index do |i, index|
    [i*i, index*index]
  end
  assert_equal [1,2,3], a
  assert_equal [[1,0],[4,1],[9,4]], c
end

assert 'Enumerable#find_all' do
  assert_equal [[3,4]], [[1,2],[3,4],[5,6]].find_all.each{ |i| i[1] == 4 }
end

assert 'Array#each_index' do
  a = [1,2,3]
  b = a.each_index
  c = []
  b.with_index do |index1,index2|
    c << [index1+2,index2+5]
  end
  assert_equal [1,2,3], a
  assert_equal [[2,5],[3,6],[4,7]], c
end

assert 'Array#map!' do
  a = [1,2,3]
  b = a.map!
  b.with_index do |i, index|
    [i*i, index*index]
  end
  assert_equal [[1,0],[4,1],[9,4]], a
end

assert 'Hash#each' do
  a = {a:1,b:2}
  b = a.each
  c = []
  b.each do |k,v|
    c << [k,v]
  end
  assert_equal [[:a,1], [:b,2]], c.sort
end

assert 'Hash#each_key' do
  assert_equal [:a,:b], {a:1,b:2}.each_key.to_a.sort
end

assert 'Hash#each_value' do
  assert_equal [1,2], {a:1,b:2}.each_value.to_a.sort
end

assert 'Hash#select' do
  h = {1=>2,3=>4,5=>6}
  hret = h.select.with_index {|a,_b| a[1] == 4}
  assert_equal({3=>4}, hret)
  assert_equal({1=>2,3=>4,5=>6}, h)
end

assert 'Hash#select!' do
  h = {1=>2,3=>4,5=>6}
  hret = h.select!.with_index {|a,_b| a[1] == 4}
  assert_equal h, hret
  assert_equal({3=>4}, h)
end

assert 'Hash#reject' do
  h = {1=>2,3=>4,5=>6}
  hret = h.reject.with_index {|a,_b| a[1] == 4}
  assert_equal({1=>2,5=>6}, hret)
  assert_equal({1=>2,3=>4,5=>6}, h)
end

assert 'Hash#reject!' do
  h = {1=>2,3=>4,5=>6}
  hret = h.reject!.with_index {|a,_b| a[1] == 4}
  assert_equal h, hret
  assert_equal({1=>2,5=>6}, h)
end

assert 'Range#each' do
  a = (1..5)
  b = a.each
  c = []
  b.each do |i|
    c << i
  end
  assert_equal [1,2,3,4,5], c
end

assert 'Enumerable#zip' do
  assert_equal [[1, 10], [2, 11], [3, 12]], [1,2,3].zip(10..Float::INFINITY)

  ret = []
  assert_equal nil, [1,2,3].zip(10..Float::INFINITY) { |i| ret << i }
  assert_equal [[1, 10], [2, 11], [3, 12]], ret

  assert_raise(TypeError) { [1].zip(1) }
end

assert 'Enumerator.produce' do
  assert_raise(ArgumentError) { Enumerator.produce }

  # Without initial object
  passed_args = []
  enum = Enumerator.produce {|obj| passed_args << obj; (obj || 0).succ }
  assert_equal Enumerator, enum.class 
  assert_take [1, 2, 3], enum
  assert_equal [nil, 1, 2], passed_args

  # With initial object
  passed_args = []
  enum = Enumerator.produce(1) {|obj| passed_args << obj; obj.succ }
  assert_take [1, 2, 3], enum
  assert_equal [1, 2], passed_args

  # Raising StopIteration
  words = %w[The quick brown fox jumps over the lazy dog]
  enum = Enumerator.produce { words.shift or raise StopIteration }
  assert_equal %w[The quick brown fox jumps over the lazy dog], enum.to_a

  # Raising StopIteration
  object = [[[["abc", "def"], "ghi", "jkl"], "mno", "pqr"], "stuv", "wxyz"]
  enum = Enumerator.produce(object) {|obj|
    obj.respond_to?(:first) or raise StopIteration
    obj.first
  }
  assert_nothing_raised {
    assert_equal [
      [[[["abc", "def"], "ghi", "jkl"], "mno", "pqr"], "stuv", "wxyz"],
      [[["abc", "def"], "ghi", "jkl"], "mno", "pqr"],
      [["abc", "def"], "ghi", "jkl"],
      ["abc", "def"],
      "abc",
    ], enum.to_a
  }
end
