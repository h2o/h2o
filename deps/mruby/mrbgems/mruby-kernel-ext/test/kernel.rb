assert('Kernel.fail, Kernel#fail') do
  assert_raise(RuntimeError) { fail }
  assert_raise(RuntimeError) { Kernel.fail }
end

assert('Kernel.caller, Kernel#caller') do
  skip "backtrace isn't available" if caller(0).empty?

  caller_lineno = __LINE__ + 3
  c = Class.new do
    def foo(*args)
      caller(*args)
    end

    def bar(*args)
      foo(*args)
    end

    def baz(*args)
      bar(*args)
    end
  end
  assert_equal "kernel.rb:#{caller_lineno}:in foo", c.new.baz(0)[0][-19..-1]
  assert_equal "bar", c.new.baz[0][-3..-1]
  assert_equal "foo", c.new.baz(0)[0][-3..-1]
  assert_equal "bar", c.new.baz(1)[0][-3..-1]
  assert_equal "baz", c.new.baz(2)[0][-3..-1]
  assert_equal ["foo", "bar"], c.new.baz(0, 2).map { |i| i[-3..-1] }
  assert_equal ["bar", "baz"], c.new.baz(1..2).map { |i| i[-3..-1] }
  assert_nil c.new.baz(10..20)
  assert_raise(ArgumentError) { c.new.baz(-1) }
  assert_raise(ArgumentError) { c.new.baz(-1, 1) }
  assert_raise(ArgumentError) { c.new.baz(1, -1) }
  assert_raise(TypeError) { c.new.baz(nil) }
end

assert('Kernel#__method__') do
  assert_equal(:m, Class.new {def m; __method__; end}.new.m)
  assert_equal(:m, Class.new {define_method(:m) {__method__}}.new.m)
  c = Class.new do
    [:m1, :m2].each do |m|
      define_method(m) do
        __method__
      end
    end
  end
  assert_equal(:m1, c.new.m1)
  assert_equal(:m2, c.new.m2)
end

assert('Kernel#Integer') do
  assert_equal(123, Integer(123.999))
  assert_equal(26, Integer("0x1a"))
  assert_equal(930, Integer("0930", 10))
  assert_equal(7, Integer("111", 2))
  assert_equal(0, Integer("0"))
  assert_equal(0, Integer("00000"))
  assert_raise(TypeError) { Integer(nil) }
end

assert('Kernel#Float') do
  assert_equal(1.0, Float(1))
  assert_equal(123.456, Float(123.456))
  assert_equal(123.456, Float("123.456"))
  assert_raise(TypeError) { Float(nil) }
end

assert('Kernel#String') do
  assert_equal("main", String(self))
  assert_equal("Object", String(self.class))
  assert_equal("123456", String(123456))
end

assert('Kernel#Array') do
  assert_equal([1], Kernel.Array(1))
  assert_equal([1, 2, 3, 4, 5], Kernel.Array([1, 2, 3, 4, 5]))
  assert_equal([1, 2, 3, 4, 5], Kernel.Array(1..5))
  assert_equal([[:a, 1], [:b, 2], [:c, 3]], Kernel.Array({a:1, b:2, c:3}))
end

assert('Kernel#Hash') do
  assert_equal({}, Hash([]))
  assert_equal({}, Hash(nil))
  assert_equal({:key => :value}, Hash(key: :value))
  assert_raise(TypeError) { Hash([1, 2, 3]) }
end
