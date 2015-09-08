assert("Kernel.require") do
  # see d/required.rb
  $gvar1 = 0
  lvar1 = 0

  assert_true require(File.join(File.dirname(__FILE__), "d", "required.rb"))

  # Kernel.require can create a global variable
  assert_equal 1, $gvar0

  # Kernel.require can change value of a global variable
  assert_equal 1, $gvar1

  # Kernel.require cannot create a local variable
  assert_raise(NoMethodError) do
    lvar0
  end

  # Kernel.require cannot change value of a local variable
  assert_equal 0, lvar1

  # Kernel.require can define a toplevel procedure
  assert_equal :proc0, proc0
end
