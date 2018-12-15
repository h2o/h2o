assert("Kernel.require", "15.3.1.2.13") do
  # preparation
  $gvar1 = 0
  lvar1 = 0
  lvar2 = 0
  class MrubyRequireClass; end

  assert_raise(LoadError) do
    require "/nonexistent.rb"
  end

  ret = Tempfile.open(["mruby-require-test", ".rb"]) { |f|
    f.write <<-PROGRAM
      # global variables
      $gvar0 = 1
      $gvar1 = 1

      # toplevel local variables
      lvar0 = 1
      lvar1 = 1

      # can not read local variables
      begin
        x = lvar2
      rescue NameError => $lvar2_exc
      end

      # define a procedure
      def proc0
        :proc0
      end

      # define a new method of an existing class.
      class MrubyRequireClass
        def foo
          :foo
        end
      end
    PROGRAM
    f.flush

    require(f.path)
  }

  # Kernel.require returns true unless an exception is raised
  assert_true ret

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

  # Kernel.require cannot read a local variable
  assert_true $lvar2_exc.is_a? NameError

  # Kernel.require can define a toplevel procedure
  assert_equal :proc0, proc0

  # Kernel.require can add a method to an existing class
  # https://github.com/iij/mruby-require/issues/13
  assert_equal :foo, MrubyRequireClass.new.foo
end

$top_self = self
assert("Kernel.require #12") do
  Tempfile.open(["mruby-require-test", ".rb"]) { |f|
    f.write <<-PROGRAM
      $require_context = self
    PROGRAM
    f.flush

    require(f.path)
  }

  assert_equal $top_self, $require_context
end

assert("Kernel.require #22") do
  $gvar2 = 0
  Tempfile.open(["mruby-require-test", ".rb"]) { |f|
    f.write <<-PROGRAM
      $gvar2 += 1
    PROGRAM
    f.flush

    require(f.path)
    require("/./" + f.path)
  }

  assert_equal 1, $gvar2
end
