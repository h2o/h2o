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
