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

  skip "backtrace isn't available" if (c.new.baz(0)[0].include?("unknown"))

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
  c = Class.new do
    def m1; __method__ end
    define_method(:m2) {__method__}
    alias m3 m1
    alias_method :m4, :m2
  end
  assert_equal(:m1, c.new.m1)
  assert_equal(:m2, c.new.m2)
  assert_equal(:m1, c.new.m3)
  assert_equal(:m2, c.new.m4)
end

assert('Kernel#__callee__') do
  c = Class.new do
    def m1; __callee__ end
    define_method(:m2) {__callee__}
    alias m3 m1
    alias_method :m4, :m2
  end
  assert_equal(:m1, c.new.m1)
  assert_equal(:m2, c.new.m2)
  assert_equal(:m3, c.new.m3)
  assert_equal(:m4, c.new.m4)
end

assert('Kernel#Integer') do
  assert_operator(26, :eql?, Integer("0x1a"))
  assert_operator(930, :eql?, Integer("0930", 10))
  assert_operator(7, :eql?, Integer("111", 2))
  assert_operator(0, :eql?, Integer("0"))
  assert_operator(0, :eql?, Integer("00000"))
  assert_operator(123, :eql?, Integer('1_2_3'))
  assert_operator(123, :eql?, Integer("\t\r\n\f\v 123 \t\r\n\f\v"))
  assert_raise(TypeError) { Integer(nil) }
  assert_raise(ArgumentError) { Integer('a') }
  assert_raise(ArgumentError) { Integer('4a5') }
  assert_raise(ArgumentError) { Integer('1_2__3') }
  assert_raise(ArgumentError) { Integer('68_') }
  assert_raise(ArgumentError) { Integer('68_ ') }
  assert_raise(ArgumentError) { Integer('_68') }
  assert_raise(ArgumentError) { Integer(' _68') }
  assert_raise(ArgumentError) { Integer('6 8') }
  assert_raise(ArgumentError) { Integer("15\0") }
  assert_raise(ArgumentError) { Integer("15.0") }
  skip unless Object.const_defined?(:Float)
  assert_operator(123, :eql?, Integer(123.999))
end

assert('Kernel#Float') do
  skip unless Object.const_defined?(:Float)
  assert_operator(1.0, :eql?, Float(1))
  assert_operator(123.456, :eql?, Float(123.456))
  assert_operator(123.456, :eql?, Float("123.456"))
  assert_operator(123.0, :eql?, Float('1_2_3'))
  assert_operator(12.34, :eql?, Float('1_2.3_4'))
  assert_operator(0.9, :eql?, Float('.9'))
  assert_operator(0.9, :eql?, Float(" \t\r\n\f\v.9 \t\r\n\f\v"))
  assert_operator(16.0, :eql?, Float("0x10"))
  assert_raise(TypeError) { Float(nil) }
  assert_raise(ArgumentError) { Float("1. 5") }
  assert_raise(ArgumentError) { Float("1.5a") }
  assert_raise(ArgumentError) { Float("1.5\0") }
  assert_raise(ArgumentError) { Float('a') }
  assert_raise(ArgumentError) { Float('4a5') }
  assert_raise(ArgumentError) { Float('1_2__3') }
  assert_raise(ArgumentError) { Float('68_') }
  assert_raise(ArgumentError) { Float('68._7') }
  assert_raise(ArgumentError) { Float('68.7_') }
  assert_raise(ArgumentError) { Float('68.7_ ') }
  assert_raise(ArgumentError) { Float('_68') }
  assert_raise(ArgumentError) { Float(' _68') }
  assert_raise(ArgumentError) { Float('1_2.3__4') }
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
