assert "Proc#binding" do
  block = ->(i) {}
  a, b, c = 1, 2, 3
  bind = block.binding
  assert_equal([:a, :b, :bind, :block, :c], bind.local_variables.sort)
  assert_equal(1, bind.local_variable_get(:a))
  assert_equal(5, bind.eval("b + c"))
  bind.local_variable_set(:x, 9)
  assert_equal(9, bind.local_variable_get(:x))
end

assert("Binding#source_location after Proc#binding") do
  skip unless -> {}.source_location

  block, source_location = -> {}, [__FILE__, __LINE__]
  assert_equal source_location, block.binding.source_location
end

assert "Proc#binding and .eval from C" do
  bind = proc_in_c.binding
  assert_nothing_raised { bind.eval("self") }
end
