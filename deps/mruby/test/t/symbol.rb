##
# Symbol ISO Test

assert('Symbol') do
  assert_equal :"a", :a
  assert_equal :"a#{1}", :a1
  assert_equal :'a', :a
  assert_equal :'a#{1}', :"a\#{1}"
end

assert('Symbol', '15.2.11') do
  assert_equal Class, Symbol.class
end

assert('Symbol#===', '15.2.11.3.1') do
  assert_true :abc === :abc
  assert_false :abc === :cba
end

assert('Symbol#to_s', '15.2.11.3.3') do
  assert_equal  'abc', :abc.to_s
end

assert('Symbol#to_sym', '15.2.11.3.4') do
  assert_equal :abc, :abc.to_sym
end

assert('Symbol#to_proc') do
  assert_equal 5, :abs.to_proc[-5]
end
