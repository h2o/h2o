assert("Kernel.load") do
  assert_raise(LoadError) do
    load "/nonexistent.rb"
  end

  $load_count = 0
  ret = Tempfile.open(["mruby-require-test", ".rb"]) { |f|
    f.write <<-PROGRAM
      $load_count += 1
    PROGRAM
    f.flush

    load f.path
    load f.path
    load f.path
  }

  assert_true ret
  assert_equal 3, $load_count
end
