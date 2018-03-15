assert 'Module#name' do
  module Outer
    class Inner; end
    const_set :SetInner, Class.new
  end

  assert_equal 'Outer', Outer.name
  assert_equal 'Outer::Inner', Outer::Inner.name
  assert_equal 'Outer::SetInner', Outer::SetInner.name

  outer = Module.new do
    const_set :SetInner, Class.new
  end
  Object.const_set :SetOuter, outer

  assert_equal 'SetOuter', SetOuter.name
  assert_equal 'SetOuter::SetInner', SetOuter::SetInner.name

  mod = Module.new
  cls = Class.new

  assert_nil mod.name
  assert_nil cls.name
end

assert 'Module#singleton_class?' do
  mod = Module.new
  cls = Class.new
  scl = cls.singleton_class

  assert_false mod.singleton_class?
  assert_false cls.singleton_class?
  assert_true scl.singleton_class?
end

assert 'Module#module_eval' do
  mod = Module.new
  mod.class_exec(1,2,3) do |a,b,c|
    assert_equal([1,2,3], [a,b,c])
    def hi
      "hi"
    end
  end
  cls = Class.new
  cls.class_exec(42) do |x|
    assert_equal(42, x)
    include mod
    def hello
      "hello"
    end
  end
  obj = cls.new
  assert_equal("hi", obj.hi)
  assert_equal("hello", obj.hello)
end
