##
# NoMethodError ISO Test

assert('NoMethodError', '15.2.32') do
  NoMethodError.class == Class
  assert_raise NoMethodError do
    doesNotExistAsAMethodNameForVerySure("")
  end
end

assert('NoMethodError#args', '15.2.32.2.1') do
  a = NoMethodError.new 'test', :test, [1, 2]
  assert_equal [1, 2], a.args

  assert_nothing_raised do
    begin
      doesNotExistAsAMethodNameForVerySure 3, 1, 4
    rescue NoMethodError => e
      assert_equal [3, 1, 4], e.args
    end
  end
end
