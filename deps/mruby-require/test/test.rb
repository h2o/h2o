$" = [] # init

assert "Kernel#_load_rb_str" do
  assert_equal true, self.methods.include?(:_load_rb_str)
  assert_equal false, Object.const_defined?(:LOAD_RB_STR_TEST)
  _load_rb_str("LOAD_RB_STR_TEST = 1")
  assert_equal true, Object.const_defined?(:LOAD_RB_STR_TEST)
end

assert "$LOAD_PATH check" do
  assert_equal Array, $LOAD_PATH.class
end

assert '$" check' do
  assert_equal [], $"
end

assert('load - error check') do
  assert_raise TypeError, "load(nil) should raise TypeError" do
    load nil
  end
  assert_raise LoadError, "load('notfound') should raise LoadError" do
    load 'notfound'
  end
end

assert('require - error check') do
  assert_raise TypeError, "require(nil) should raise TypeError" do
    require nil
  end
  assert_raise LoadError, "require('notfound') should raise LoadError" do
    require "notfound"
  end
end
