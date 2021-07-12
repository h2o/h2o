# coding: utf-8
##
# Symbol(Ext) Test

if Symbol.respond_to?(:all_symbols)
  assert('Symbol.all_symbols') do
    foo = [:__symbol_test_1, :__symbol_test_2, :__symbol_test_3].sort
    symbols = Symbol.all_symbols.select{|sym|sym.to_s.include? '__symbol_test'}.sort
    assert_equal foo, symbols
  end
end

%w[size length].each do |n|
  assert("Symbol##{n}") do
    assert_equal 5, :hello.__send__(n)
    assert_equal 4, :"aA\0b".__send__(n)
    if __ENCODING__ == "UTF-8"
      assert_equal 8, :"こんにちは世界!".__send__(n)
      assert_equal 4, :"aあ\0b".__send__(n)
    else
      assert_equal 22, :"こんにちは世界!".__send__(n)
      assert_equal 6, :"aあ\0b".__send__(n)
    end
  end
end

assert("Symbol#capitalize") do
  assert_equal :Hello, :hello.capitalize
  assert_equal :Hello, :HELLO.capitalize
  assert_equal :Hello, :Hello.capitalize
end

assert("Symbol#downcase") do
  assert_equal :hello, :hEllO.downcase
  assert_equal :hello, :hello.downcase
end

assert("Symbol#upcase") do
  assert_equal :HELLO, :hEllO.upcase
  assert_equal :HELLO, :HELLO.upcase
end

assert("Symbol#casecmp") do
  assert_equal 0, :HELLO.casecmp(:hEllO)
  assert_equal 1, :HELLO.casecmp(:hEllN)
  assert_equal(-1, :HELLO.casecmp(:hEllP))
  assert_nil :HELLO.casecmp("hEllO")
end

assert("Symbol#empty?") do
  assert_true :''.empty?
end

assert('Symbol#intern') do
  assert_equal :test, :test.intern
end
