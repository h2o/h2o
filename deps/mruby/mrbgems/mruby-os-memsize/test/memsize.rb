assert 'ObjectSpace.memsize_of' do
  # immediate literals
  int_size = ObjectSpace.memsize_of 1
  assert_equal int_size, 0, 'int zero'

  sym_size = ObjectSpace.memsize_of :foo
  assert_equal sym_size, 0, 'sym zero'

  assert_equal ObjectSpace.memsize_of(true), int_size
  assert_equal ObjectSpace.memsize_of(false), int_size

  assert_not_equal ObjectSpace.memsize_of('a'), 0, 'memsize of str'

  if __ENCODING__ == "UTF-8"
    assert_not_equal ObjectSpace.memsize_of("こんにちは世界"), 0, 'memsize of utf8 str'
  end

  # class defs
  class_obj_size = ObjectSpace.memsize_of Class
  assert_not_equal class_obj_size, 0, 'Class obj not zero'

  empty_class_def_size = ObjectSpace.memsize_of Class.new
  assert_not_equal empty_class_def_size, 0, 'Class def not zero'

  proc_size = ObjectSpace.memsize_of Proc.new { x = 1; x }
  assert_not_equal proc_size, 0

  class_with_methods = Class.new do
    def foo
      a = 0
      a + 1
    end
  end

  m_size = ObjectSpace.memsize_of class_with_methods.instance_method(:foo)
  assert_not_equal m_size, 0, 'method size not zero'

  # collections
  empty_array_size = ObjectSpace.memsize_of []
  assert_not_equal empty_array_size, 0, 'empty array size not zero'
  assert_operator empty_array_size, :<, ObjectSpace.memsize_of(Array.new(16)), 'large array size greater than embed'

  # fiber
  empty_fiber_size = ObjectSpace.memsize_of(Fiber.new {})
  assert_not_equal empty_fiber_size, 0, 'empty fiber not zero'

  #hash
  assert_not_equal ObjectSpace.memsize_of({}), 0, 'empty hash size not zero'
end

assert 'ObjectSpace.memsize_of_all' do
  foo_class = Class.new do
    def initialize
      @a = 'a'
      @b = 'b'
    end
  end

  foos = Array.new(10) { foo_class.new }
  foo_size = ObjectSpace.memsize_of(foos.first)

  assert_equal ObjectSpace.memsize_of_all(foo_class), foo_size * foos.size, 'Memsize of all instance'
end
