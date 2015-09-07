##
# Struct ISO Test

assert('Struct', '15.2.18') do
  Struct.class == Class
end

assert('Struct.new', '15.2.18.3.1') do
  c = Struct.new(:m1, :m2)
  c.superclass == Struct and
    c.members == [:m1,:m2]
end

# Check crash bug with Struc.new and no params.
assert('Struct.new', '15.2.18.3.1') do
  c = Struct.new()
  c.superclass == Struct and c.members == []
end

assert('Struct#==', '15.2.18.4.1') do
  c = Struct.new(:m1, :m2)
  cc1 = c.new(1,2)
  cc2 = c.new(1,2)
  cc1 == cc2
end

assert('Struct#[]', '15.2.18.4.2') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  cc[:m1] == 1 and cc["m2"] == 2
end

assert('Struct#[]=', '15.2.18.4.3') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  cc[:m1] = 3
  cc[:m1] == 3
  cc["m2"] = 3
  assert_equal 3, cc["m2"]
  assert_raise(TypeError) { cc[[]] = 3 }
end

assert('Struct#each', '15.2.18.4.4') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  a = []
  cc.each{|x|
    a << x
  }
  a[0] == 1 and a[1] == 2
end

assert('Struct#each_pair', '15.2.18.4.5') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  a = []
  cc.each_pair{|k,v|
    a << [k,v]
  }
  a[0] == [:m1, 1] and a[1] == [:m2, 2]
end

assert('Struct#members', '15.2.18.4.6') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  cc.members == [:m1,:m2]
end

assert('Struct#select', '15.2.18.4.7') do
  c = Struct.new(:m1, :m2)
  cc = c.new(1,2)
  cc.select{|v| v % 2 == 0} == [2]
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

assert('struct inspect') do
  c = Struct.new(:m1, :m2, :m3, :m4, :m5)
  cc = c.new(1,2,3,4,5)
  assert_equal "#<struct #{c.inspect} m1=1, m2=2, m3=3, m4=4, m5=5>", cc.inspect
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
