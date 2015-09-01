##
# Hash(Ext) Test

assert('Hash.[] Hash') do
  a = Hash['a_key' => 'a_value']

  assert_equal({'a_key' => 'a_value'}, a)
end

assert('Hash.[] [ [ ["b_key", "b_value" ] ] ]') do
  a = Hash[ [ ['b_key', 'b_value'] ] ]

  assert_equal({'b_key' => 'b_value'}, a)

  a = Hash[ [ ] ]

  assert_equal({}, a)

  assert_raise(ArgumentError) do
    Hash[ [ ['b_key', 'b_value', 'b_over'] ] ]
  end

  assert_raise(ArgumentError) do
    Hash[ [ [] ] ]
  end
end

assert('Hash.[] "c_key", "c_value"') do
  a = Hash['c_key', 'c_value', 'd_key', 1]

  assert_equal({'c_key' => 'c_value', 'd_key' => 1}, a)

  a = Hash[]

  assert_equal({}, a)

  assert_raise(ArgumentError) do
    Hash['d_key']
  end
end

assert('Hash#merge!') do
  a = { 'abc_key' => 'abc_value', 'cba_key' => 'cba_value' }
  b = { 'cba_key' => 'XXX',  'xyz_key' => 'xyz_value' }

  result_1 = a.merge! b

  a = { 'abc_key' => 'abc_value', 'cba_key' => 'cba_value' }
  result_2 = a.merge!(b) do |key, original, new|
    original
  end

  assert_equal({'abc_key' => 'abc_value', 'cba_key' => 'XXX',
               'xyz_key' => 'xyz_value' }, result_1)
  assert_equal({'abc_key' => 'abc_value', 'cba_key' => 'cba_value',
               'xyz_key' => 'xyz_value' }, result_2)

  assert_raise(TypeError) do
    { 'abc_key' => 'abc_value' }.merge! "a"
  end
end

assert('Hash#values_at') do
  h = { "cat" => "feline", "dog" => "canine", "cow" => "bovine" }
  assert_equal ["bovine", "feline"], h.values_at("cow", "cat")

  keys = []
  (0...1000).each { |v| keys.push "#{v}" }
  h = Hash.new { |hash,k| hash[k] = k }
  assert_equal keys, h.values_at(*keys)
end

assert('Hash#fetch') do
  h = { "cat" => "feline", "dog" => "canine", "cow" => "bovine" }
  assert_equal "feline", h.fetch("cat")
  assert_equal "mickey", h.fetch("mouse", "mickey")
  assert_equal "minny", h.fetch("mouse"){"minny"}
  begin
    h.fetch("gnu")
  rescue => e
    assert_kind_of(StandardError, e);
  end
end

assert("Hash#delete_if") do
  base = { 1 => 'one', 2 => false, true => 'true', 'cat' => 99 }
  h1   = { 1 => 'one', 2 => false, true => 'true' }
  h2   = { 2 => false, 'cat' => 99 }
  h3   = { 2 => false }

  h = base.dup
  assert_equal(h, h.delete_if { false })
  assert_equal({}, h.delete_if { true })

  h = base.dup
  assert_equal(h1, h.delete_if {|k,v| k.instance_of?(String) })
  assert_equal(h1, h)

  h = base.dup
  assert_equal(h2, h.delete_if {|k,v| v.instance_of?(String) })
  assert_equal(h2, h)

  h = base.dup
  assert_equal(h3, h.delete_if {|k,v| v })
  assert_equal(h3, h)

  h = base.dup
  n = 0
  h.delete_if {|*a|
    n += 1
    assert_equal(2, a.size)
    assert_equal(base[a[0]], a[1])
    h.shift
    true
  }
  assert_equal(base.size, n)
end

assert("Hash#flatten") do
  a =  {1=> "one", 2 => [2,"two"], 3 => [3, ["three"]]}
  assert_equal [1, "one", 2, [2, "two"], 3, [3, ["three"]]], a.flatten
  assert_equal [[1, "one"], [2, [2, "two"]], [3, [3, ["three"]]]], a.flatten(0)
  assert_equal [1, "one", 2, [2, "two"], 3, [3, ["three"]]], a.flatten(1)
  assert_equal [1, "one", 2, 2, "two", 3, 3, ["three"]], a.flatten(2)
  assert_equal [1, "one", 2, 2, "two", 3, 3, "three"], a.flatten(3)
end

assert("Hash#invert") do
  h = { 1 => 'one', 2 => 'two', 3 => 'three',
        true => 'true', nil => 'nil' }.invert
  assert_equal 1, h['one']
  assert_equal true, h['true']
  assert_equal nil, h['nil']

  h = { 'a' => 1, 'b' => 2, 'c' => 1 }.invert
  assert_equal(2, h.length)
  assert_include(%w[a c], h[1])
  assert_equal('b', h[2])
end

assert("Hash#keep_if") do
  h = { 1 => 2, 3 => 4, 5 => 6 }
  assert_equal({3=>4,5=>6}, h.keep_if {|k, v| k + v >= 7 })
  h = { 1 => 2, 3 => 4, 5 => 6 }
  assert_equal({ 1 => 2, 3=> 4, 5 =>6} , h.keep_if { true })
end

assert("Hash#key") do
  h = { "a" => 100, "b" => 200, "c" => 300, "d" => 300, nil => 'nil', 'nil' => nil }
  assert_equal "b", h.key(200)
  assert_equal "c", h.key(300)
  assert_nil h.key(999)
  assert_nil h.key('nil')
  assert_equal 'nil', h.key(nil)
end

assert("Hash#to_h") do
  h = { "a" => 100, "b" => 200 }
  assert_equal Hash, h.to_h.class
  assert_equal h, h.to_h
end
