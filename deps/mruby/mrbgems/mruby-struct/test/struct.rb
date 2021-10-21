##
# Struct ISO Test

assert('Struct', '15.2.18') do
  assert_equal Class, Struct.class
end

assert('Struct.new', '15.2.18.3.1') do
  c = Struct.new(:m1, :m2)
  assert_equal Struct, c.superclass
  assert_equal [:m1, :m2], c.members
end

assert('Struct#==', '15.2.18.4.1') do
  c = Struct.new(:m1, :m2)
  cc1 = c.new(1,2)
  cc2 = c.new(1,2)
  assert_true cc1 == cc2

  Struct.new(:m1, :m2) { def foo; end }
  assert_raise(NoMethodError) { Struct.new(:m1).new.foo }
end

assert('Struct#[]', '15.2.18.4.2') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  assert_equal 1, cc[:m1]
  assert_equal 2, cc["m2"]
  assert_equal 1, cc[0]
  assert_equal 2, cc[-1]
  assert_raise(TypeError) { cc[[]] }
  assert_raise(IndexError) { cc[2] }
  assert_raise(NameError) { cc['tama'] }
end

assert('Struct#[]=', '15.2.18.4.3') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  cc[:m1] = 3
  assert_equal 3, cc[:m1]
  cc["m2"] = 3
  assert_equal 3, cc["m2"]
  cc[0] = 4
  assert_equal 4, cc[0]
  cc[-1] = 5
  assert_equal 5, cc[-1]
  assert_raise(TypeError) { cc[[]] = 3 }
  assert_raise(IndexError) { cc[2] = 7 }
  assert_raise(NameError) { cc['pochi'] = 8 }
end

assert('Struct#each', '15.2.18.4.4') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  a = []
  cc.each{|x|
    a << x
  }
  assert_equal [1, 2], a
end

assert('Struct#each_pair', '15.2.18.4.5') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  a = []
  cc.each_pair{|k,v|
    a << [k,v]
  }
  assert_equal [[:m1, 1], [:m2, 2]], a
end

assert('Struct#members', '15.2.18.4.6') do
  c = Struct.new(:m1, :m2)
  assert_equal [:m1, :m2], c.new(1,2).members
end

assert('Struct#select', '15.2.18.4.7') do
  c = Struct.new(:m1, :m2)
  assert_equal([2]) { c.new(1,2).select{|v| v % 2 == 0} }
end

assert('large struct') do
  c = Struct.new(:m1, :m2, :m3, :m4, :m5, :m6, :m7, :m8, :m9, :m10, :m11, :m12, :m13)
  cc = c.new(1,2,3,4,5,6,7,8,9,10,11,12,13)
  assert_equal 1, cc.m1
  assert_equal 2, cc.m2
  assert_equal 3, cc.m3
  assert_equal 4, cc.m4
  assert_equal 5, cc.m5
  assert_equal 6, cc.m6
  assert_equal 7, cc.m7
  assert_equal 8, cc.m8
  assert_equal 9, cc.m9
  assert_equal 10, cc.m10
  assert_equal 13, cc.m13

  cc.m13 = 'test'
  assert_equal 'test', cc.m13

  assert_raise(NoMethodError) { cc.m14 }
end

assert('wrong struct arg count') do
  c = Struct.new(:m1)
  assert_raise ArgumentError do
    cc = c.new(1,2,3)
  end
end

assert('struct dup') do
  c = Struct.new(:m1, :m2, :m3, :m4, :m5)
  cc = c.new(1,2,3,4,5)
  assert_nothing_raised {
    assert_equal(cc, cc.dup)
  }
end

assert('struct inspect') do
  c = Struct.new(:m1, :m2, :m3, :m4, :m5)
  cc = c.new(1,2,3,4,5)
  assert_equal "#<struct m1=1, m2=2, m3=3, m4=4, m5=5>", cc.inspect
end

assert('Struct#length, Struct#size') do
  s = Struct.new(:f1, :f2).new(0, 1)
  assert_equal 2, s.size
  assert_equal 2, s.length
end

assert('Struct#to_a, Struct#values') do
  s = Struct.new(:mem1, :mem2).new('a', 'b')
  assert_equal ['a', 'b'], s.to_a
  assert_equal ['a', 'b'], s.values
end

assert('Struct#to_h') do
  s = Struct.new(:white, :red, :green).new('ruuko', 'yuzuki', 'hitoe')
  assert_equal(:white => 'ruuko', :red => 'yuzuki', :green => 'hitoe') { s.to_h }
end

assert('Struct#values_at') do
  a = Struct.new(:blue, :purple).new('aki', 'io')
  assert_equal ['aki'], a.values_at(0)
  assert_equal ['io', 'aki'], a.values_at(1, 0)
  assert_raise(IndexError) { a.values_at 2 }
end

assert("Struct#dig") do
  a = Struct.new(:blue, :purple).new('aki', Struct.new(:red).new(1))
  assert_equal 'aki', a.dig(:blue)
  assert_equal 1, a.dig(:purple, :red)
  assert_equal 1, a.dig(1, 0)
end

assert("Struct.new removes existing constant") do
  skip "redefining Struct with same name cause warnings"
  begin
    assert_not_equal Struct.new("Test", :a), Struct.new("Test", :a, :b)
  ensure
    Struct.remove_const :Test
  end
end

assert("Struct#initialize_copy requires struct to be the same type") do
  begin
    Struct.new("Test", :a)
    a = Struct::Test.new("a")
    Struct.remove_const :Test
    Struct.new("Test", :a, :b)
    assert_raise(TypeError) do
      a.initialize_copy(Struct::Test.new("a", "b"))
    end
  ensure
    Struct.remove_const :Test
  end
end

assert("Struct.new does not allow array") do
  assert_raise(TypeError) do
    Struct.new("Test", [:a])
  end
end

assert("Struct.new generates subclass of Struct") do
  begin
    original_struct = Struct
    Struct = String
    assert_equal original_struct, original_struct.new(:foo).superclass
  ensure
    Struct = original_struct
  end
end

assert 'Struct#freeze' do
  c = Struct.new :m

  o = c.new
  o.m = :test
  assert_equal :test, o.m

  o.freeze
  assert_raise(RuntimeError) { o.m = :modify }
  assert_raise(RuntimeError) { o[:m] = :modify }
  assert_equal :test, o.m
end
