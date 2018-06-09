assert('ObjectSpace.count_objects') do
  h = {}
  f = Fiber.new {} if Object.const_defined? :Fiber
  ObjectSpace.count_objects(h)
  assert_kind_of(Hash, h)
  assert_true(h.keys.all? {|x| x.is_a?(Symbol) || x.is_a?(Integer) })
  assert_true(h.values.all? {|x| x.is_a?(Integer) })

  assert_true(h.has_key?(:TOTAL))
  assert_true(h.has_key?(:FREE))
  assert_true(h.has_key?(:T_FIBER)) if Object.const_defined? :Fiber

  assert_equal(h[:TOTAL] * 2, h.values.reduce(:+))

  h = ObjectSpace.count_objects
  assert_kind_of(Hash, h)
  assert_true(h.keys.all? {|x| x.is_a?(Symbol) || x.is_a?(Integer) })
  assert_true(h.values.all? {|x| x.is_a?(Integer) })

  assert_raise(TypeError) { ObjectSpace.count_objects(1) }

  h0 = {:T_FOO=>1000}
  h = ObjectSpace.count_objects(h0)
  assert_false(h0.has_key?(:T_FOO))

  GC.start
  h_after = {}
  h_before = ObjectSpace.count_objects

  objs = []
  1000.times do
    objs << {}
  end
  ObjectSpace.count_objects(h)
  objs = nil
  GC.start
  ObjectSpace.count_objects(h_after)

  assert_equal(h[:T_HASH], h_before[:T_HASH] + 1000)
  assert_equal(h_after[:T_HASH], h_before[:T_HASH])
end

assert('ObjectSpace.each_object') do
  objs = []
  objs_count = ObjectSpace.each_object { |obj|
    objs << obj
  }
  assert_equal objs.length, objs_count

  arys = []
  arys_count = ObjectSpace.each_object(Array) { |obj|
    arys << obj
  }
  assert_equal arys.length, arys_count
  assert_true arys.length < objs.length
end

assert 'Check class pointer of ObjectSpace.each_object.' do
  ObjectSpace.each_object { |obj| !obj }
end
