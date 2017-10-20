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

assert('Hash.[] for sub class') do
  sub_hash_class = Class.new(Hash)
  sub_hash = sub_hash_class[]
  assert_equal(sub_hash_class, sub_hash.class)
end

assert('Hash.try_convert') do
  assert_nil Hash.try_convert(nil)
  assert_nil Hash.try_convert("{1=>2}")
  assert_equal({1=>2}, Hash.try_convert({1=>2}))
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

assert('Hash#compact') do
  h = { "cat" => "feline", "dog" => nil, "cow" => false }

  assert_equal({ "cat" => "feline", "cow" => false }, h.compact)
  assert_equal({ "cat" => "feline", "dog" => nil, "cow" => false }, h)
end

assert('Hash#compact!') do
  h = { "cat" => "feline", "dog" => nil, "cow" => false }

  h.compact!
  assert_equal({ "cat" => "feline", "cow" => false }, h)
end

assert('Hash#fetch') do
  h = { "cat" => "feline", "dog" => "canine", "cow" => "bovine" }
  assert_equal "feline", h.fetch("cat")
  assert_equal "mickey", h.fetch("mouse", "mickey")
  assert_equal "minny", h.fetch("mouse"){"minny"}
  assert_equal "mouse", h.fetch("mouse"){|k| k}
  assert_raise(KeyError) do
    h.fetch("gnu")
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

assert("Hash#invert with sub class") do
  sub_hash_class = Class.new(Hash)
  sub_hash = sub_hash_class.new
  assert_equal(sub_hash_class, sub_hash.invert.class)
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

assert('Hash#<') do
  h1 = {a:1, b:2}
  h2 = {a:1, b:2, c:3}

  assert_false(h1 < h1)
  assert_true(h1 < h2)
  assert_false(h2 < h1)
  assert_false(h2 < h2)

  h1 = {a:1}
  h2 = {a:2}

  assert_false(h1 < h1)
  assert_false(h1 < h2)
  assert_false(h2 < h1)
  assert_false(h2 < h2)
end

assert('Hash#<=') do
  h1 = {a:1, b:2}
  h2 = {a:1, b:2, c:3}

  assert_true(h1 <= h1)
  assert_true(h1 <= h2)
  assert_false(h2 <= h1)
  assert_true(h2 <= h2)

  h1 = {a:1}
  h2 = {a:2}

  assert_true(h1 <= h1)
  assert_false(h1 <= h2)
  assert_false(h2 <= h1)
  assert_true(h2 <= h2)
end

assert('Hash#>=') do
  h1 = {a:1, b:2}
  h2 = {a:1, b:2, c:3}

  assert_true(h1 >= h1)
  assert_false(h1 >= h2)
  assert_true(h2 >= h1)
  assert_true(h2 >= h2)

  h1 = {a:1}
  h2 = {a:2}

  assert_true(h1 >= h1)
  assert_false(h1 >= h2)
  assert_false(h2 >= h1)
  assert_true(h2 >= h2)
end

assert('Hash#>') do
  h1 = {a:1, b:2}
  h2 = {a:1, b:2, c:3}

  assert_false(h1 > h1)
  assert_false(h1 > h2)
  assert_true(h2 > h1)
  assert_false(h2 > h2)

  h1 = {a:1}
  h2 = {a:2}

  assert_false(h1 > h1)
  assert_false(h1 > h2)
  assert_false(h2 > h1)
  assert_false(h2 > h2)
end

assert("Hash#dig") do
  h = {a:{b:{c:1}}}
  assert_equal(1, h.dig(:a, :b, :c))
  assert_nil(h.dig(:d))
end

assert("Hash#transform_keys") do
  h = {"1" => 100, "2" => 200}
  assert_equal(h.transform_keys{|k| k+"!"},
               {"1!" => 100, "2!" => 200})
  assert_equal(h.transform_keys{|k|k.to_i},
               {1 => 100, 2 => 200})
  assert_equal(h.transform_keys.with_index{|k, i| "#{k}.#{i}"},
               {"1.0" => 100, "2.1" => 200})
  assert_equal(h.transform_keys!{|k|k.to_i}, h)
  assert_equal(h, {1 => 100, 2 => 200})
end

assert("Hash#transform_values") do
  h = {a: 1, b: 2, c: 3}
  assert_equal(h.transform_values{|v| v * v + 1},
               {a: 2, b: 5, c: 10})
  assert_equal(h.transform_values{|v|v.to_s},
               {a: "1", b: "2", c: "3"})
  assert_equal(h.transform_values.with_index{|v, i| "#{v}.#{i}"},
               {a: "1.0", b: "2.1", c: "3.2"})
  assert_equal(h.transform_values!{|v|v.to_s}, h)
  assert_equal(h, {a: "1", b: "2", c: "3"})
end
