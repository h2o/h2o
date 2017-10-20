##
# Proc(Ext) Test

assert('Proc#source_location') do
  loc = Proc.new {}.source_location
  next true if loc.nil?
  assert_equal loc[0][-7, 7], 'proc.rb'
  assert_equal loc[1], 5
end

assert('Proc#inspect') do
  ins = Proc.new{}.inspect
  assert_kind_of String, ins
end

assert('Proc#lambda?') do
  assert_true lambda{}.lambda?
  assert_true !Proc.new{}.lambda?
end

assert('Proc#===') do
  proc = Proc.new {|a| a * 2}
  assert_equal 20, (proc === 10)
end

assert('Proc#yield') do
  proc = Proc.new {|a| a * 2}
  assert_equal 20, proc.yield(10)
end

assert('Proc#curry') do
  b = proc {|x, y, z| (x||0) + (y||0) + (z||0) }
  assert_equal 6, b.curry[1][2][3]
  assert_equal 6, b.curry[1, 2][3, 4]
  assert_equal 6, b.curry(5)[1][2][3][4][5]
  assert_equal 6, b.curry(5)[1, 2][3, 4][5]
  assert_equal 1, b.curry(1)[1]

  b = lambda {|x, y, z| (x||0) + (y||0) + (z||0) }
  assert_equal 6, b.curry[1][2][3]
  assert_raise(ArgumentError) { b.curry[1, 2][3, 4] }
  assert_raise(ArgumentError) { b.curry(5) }
  assert_raise(ArgumentError) { b.curry(1) }

  assert_false(proc{}.curry.lambda?)
  assert_true(lambda{}.curry.lambda?)
end

assert('Proc#parameters') do
  assert_equal([], Proc.new {}.parameters)
  assert_equal([], Proc.new {||}.parameters)
  assert_equal([[:opt, :a]], Proc.new {|a|}.parameters)
  assert_equal([[:req, :a]], lambda {|a|}.parameters)
  assert_equal([[:opt, :a]], lambda {|a=nil|}.parameters)
  assert_equal([[:req, :a]], ->(a){}.parameters)
  assert_equal([[:rest]], lambda { |*| }.parameters)
  assert_equal([[:rest, :a]], Proc.new {|*a|}.parameters)
  assert_equal([[:opt, :a], [:opt, :b], [:opt, :c], [:opt, :d], [:rest, :e], [:opt, :f], [:opt, :g], [:block, :h]], Proc.new {|a,b,c=:c,d=:d,*e,f,g,&h|}.parameters)
  assert_equal([[:req, :a], [:req, :b], [:opt, :c], [:opt, :d], [:rest, :e], [:req, :f], [:req, :g], [:block, :h]], lambda {|a,b,c=:c,d=:d,*e,f,g,&h|}.parameters)
end

assert('Proc#to_proc') do
  proc = Proc.new {}
  assert_equal proc, proc.to_proc
end

assert('Kernel#proc') do
  assert_true !proc{|a|}.lambda?

  assert_raise LocalJumpError do
    proc{ break }.call
  end
end

assert('mrb_proc_new_cfunc_with_env') do
  ProcExtTest.mrb_proc_new_cfunc_with_env(:test)
  ProcExtTest.mrb_proc_new_cfunc_with_env(:mruby)

  t = ProcExtTest.new

  assert_equal :test, t.test
  assert_equal :mruby, t.mruby
end

assert('mrb_cfunc_env_get') do
  ProcExtTest.mrb_cfunc_env_get :get_int, [0, 1, 2]

  t = ProcExtTest.new

  assert_raise(TypeError) { t.cfunc_without_env }

  assert_raise(IndexError) { t.get_int(-1) }
  assert_raise(IndexError) { t.get_int(3) }

  assert_equal 1, t.get_int(1)
end
