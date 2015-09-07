#assert('Kernel.sprintf') do
#end

assert('String#%') do
  assert_equal "one=1", "one=%d" % 1
  assert_equal "1 one 1.0", "%d %s %3.1f" % [ 1, "one", 1.01 ]
  assert_equal "123 < 456", "%{num} < %<str>s" % { num: 123, str: "456" }
end
