assert("Kernel.#binding") do
  assert_kind_of Binding, binding
end

assert("Binding#local_variables") do
  block = Proc.new do |a|
    b = 1
    binding
  end
  assert_equal [:a, :b, :block], block.call(0).local_variables.sort
end

assert("Binding#local_variable_set") do
  bind = binding
  1.times {
    assert_equal(9, bind.local_variable_set(:x, 9))
    assert_raise(NameError) { x }
    assert_equal([:bind, :x], bind.local_variables.sort)
  }
end

assert("Binding#local_variable_get") do
  bind = binding
  x = 1
  1.times {
    y = 2
    assert_equal(1, bind.local_variable_get(:x))
    x = 10
    assert_equal(10, bind.local_variable_get(:x))
    assert_raise(NameError) { bind.local_variable_get(:y) }
    assert_equal([:bind, :x], bind.local_variables.sort)
  }
end

assert("Binding#source_location") do
  skip unless -> {}.source_location

  bind, source_location = binding, [__FILE__, __LINE__]
  assert_equal source_location, bind.source_location
end
