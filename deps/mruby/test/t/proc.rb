##
# Proc ISO Test

assert('Proc', '15.2.17') do
  assert_equal Class, Proc.class
end

assert('Proc.new', '15.2.17.3.1') do
  assert_raise ArgumentError do
    Proc.new
  end

  assert_equal (Proc.new {}).class, Proc

  assert_raise LocalJumpError do
    Proc.new{ break }.call
  end
end

assert('Proc#[]', '15.2.17.4.1') do
  a = 0
  b = Proc.new { a += 1 }
  b.[]

  a2 = 0
  b2 = Proc.new { |i| a2 += i }
  b2.[](5)

  assert_equal 1, a
  assert_equal 5, a2
end

assert('Proc#arity', '15.2.17.4.2') do
  a = Proc.new {|x, y|}.arity
  b = Proc.new {|x, *y, z|}.arity
  c = Proc.new {|x=0, y|}.arity
  d = Proc.new {|(x, y), z=0|}.arity

  assert_equal  2, a
  assert_equal(-3, b)
  assert_equal  1, c
  assert_equal  1, d

  e = ->(x=0, y){}.arity
  f = ->((x, y), z=0){}.arity
  g = ->(x=0){}.arity

  assert_equal(-2, e)
  assert_equal(-2, f)
  assert_equal(-1, g)
end

assert('Proc#call', '15.2.17.4.3') do
  a = 0
  b = Proc.new { a += 1 }
  b.call

  a2 = 0
  b2 = Proc.new { |i| a2 += i }
  b2.call(5)

  assert_equal 1, a
  assert_equal 5, a2
end

assert('Proc#call proc args pos block') do
  pr = Proc.new {|a,b,&c|
    [a, b, c.class, c&&c.call(:x)]
  }
  assert_equal [nil, nil, Proc, :proc], (pr.call(){ :proc })
  assert_equal [1, nil, Proc, :proc], (pr.call(1){ :proc })
  assert_equal [1, 2, Proc, :proc], (pr.call(1, 2){ :proc })
  assert_equal [1, 2, Proc, :proc], (pr.call(1, 2, 3){ :proc })
  assert_equal [1, 2, Proc, :proc], (pr.call(1, 2, 3, 4){ :proc })

  assert_equal [nil, nil, Proc, :x], (pr.call(){|x| x})
  assert_equal [1, nil, Proc, :x], (pr.call(1){|x| x})
  assert_equal [1, 2, Proc, :x], (pr.call(1, 2){|x| x})
  assert_equal [1, 2, Proc, :x], (pr.call(1, 2, 3){|x| x})
  assert_equal [1, 2, Proc, :x], (pr.call(1, 2, 3, 4){|x| x})
end

assert('Proc#call proc args pos rest post') do
  pr = Proc.new {|a,b,*c,d,e|
    [a,b,c,d,e]
  }
  assert_equal [nil, nil, [], nil, nil], pr.call()
  assert_equal [1, nil, [], nil, nil], pr.call(1)
  assert_equal [1, 2, [], nil, nil], pr.call(1,2)
  assert_equal [1, 2, [], 3, nil], pr.call(1,2,3)
  assert_equal [1, 2, [], 3, 4], pr.call(1,2,3,4)
  assert_equal [1, 2, [3], 4, 5], pr.call(1,2,3,4,5)
  assert_equal [1, 2, [3, 4], 5, 6], pr.call(1,2,3,4,5,6)
  assert_equal [1, 2, [3, 4, 5], 6,7], pr.call(1,2,3,4,5,6,7)

  assert_equal [nil, nil, [], nil, nil], pr.call([])
  assert_equal [1, nil, [], nil, nil], pr.call([1])
  assert_equal [1, 2, [], nil, nil], pr.call([1,2])
  assert_equal [1, 2, [], 3, nil], pr.call([1,2,3])
  assert_equal [1, 2, [], 3, 4], pr.call([1,2,3,4])
  assert_equal [1, 2, [3], 4, 5], pr.call([1,2,3,4,5])
  assert_equal [1, 2, [3, 4], 5, 6], pr.call([1,2,3,4,5,6])
  assert_equal [1, 2, [3, 4, 5], 6,7], pr.call([1,2,3,4,5,6,7])
end

assert('Proc#return_does_not_break_self') do
  class TestClass
    attr_accessor :block
    def initialize
    end
    def return_array
      @block = Proc.new { self }
      return []
    end
    def return_instance_variable
      @block = Proc.new { self }
      return @block
    end
    def return_const_fixnum
      @block = Proc.new { self }
      return 123
    end
    def return_nil
      @block = Proc.new { self }
      return nil
    end
  end

  c = TestClass.new
  assert_equal [], c.return_array
  assert_equal c, c.block.call

  c.return_instance_variable
  assert_equal c, c.block.call

  assert_equal 123, c.return_const_fixnum
  assert_equal c, c.block.call

  assert_equal nil, c.return_nil
  assert_equal c, c.block.call
end

assert('call Proc#initialize if defined') do
  a = []
  c = Class.new(Proc) do
    define_method(:initialize) do
      a << :ok
    end
  end

  assert_kind_of c, c.new{}
  assert_equal [:ok], a
end

assert('&obj call to_proc if defined') do
  pr = Proc.new{}
  def mock(&b)
    b
  end
  assert_equal pr.object_id, mock(&pr).object_id
  assert_equal pr, mock(&pr)

  obj = Object.new
  def obj.to_proc
    Proc.new{ :from_to_proc }
  end
  assert_equal :from_to_proc, mock(&obj).call

  assert_raise(TypeError){ mock(&(Object.new)) }
end

assert('Creation of a proc through the block of a method') do
  def m(&b) b end

  assert_equal m{}.class, Proc

  assert_raise LocalJumpError do
    m{ break }.call
  end
end
