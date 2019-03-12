##
# Array(Ext) Test

assert("Array#assoc") do
  s1 = [ "colors", "red", "blue", "green" ]
  s2 = [ "letters", "a", "b", "c" ]
  s3 = "foo"
  a  = [ s1, s2, s3 ]

  assert_equal [ "letters", "a", "b", "c" ], a.assoc("letters")
  assert_nil a.assoc("foo")
end

assert("Array#at") do
  a = [ "a", "b", "c", "d", "e" ]
  assert_equal "a", a.at(0)
  assert_equal "e", a.at(-1)
end

assert("Array#rassoc") do
  a = [ [ 1, "one"], [2, "two"], [3, "three"], ["ii", "two"] ]

  assert_equal [2, "two"], a.rassoc("two")
  assert_nil a.rassoc("four")
end

assert("Array#uniq!") do
  a = [1, 2, 3, 1]
  a.uniq!
  assert_equal [1, 2, 3], a

  b = [ "a", "b", "c" ]
  assert_nil b.uniq!

  c = [["student","sam"], ["student","george"], ["teacher","matz"]]
  assert_equal [["student", "sam"], ["teacher", "matz"]], c.uniq! { |s| s.first }

  d = [["student","sam"], ["teacher","matz"]]
  assert_nil d.uniq! { |s| s.first }
end

assert("Array#uniq") do
  a = [1, 2, 3, 1]
  assert_equal [1, 2, 3], a.uniq
  assert_equal [1, 2, 3, 1], a

  b = [["student","sam"], ["student","george"], ["teacher","matz"]]
  assert_equal [["student", "sam"], ["teacher", "matz"]], b.uniq { |s| s.first }
end

assert("Array#-") do
  a = [1, 2, 3, 1]
  b = [1]
  c = 1

  assert_raise(TypeError) { a - c }
  assert_equal [2, 3], (a - b)
  assert_equal [1, 2, 3, 1], a
end

assert("Array#|") do
  a = [1, 2, 3, 1]
  b = [1, 4]
  c = 1

  assert_raise(TypeError) { a | c }
  assert_equal [1, 2, 3, 4], (a | b)
  assert_equal [1, 2, 3, 1], a
end

assert("Array#union") do
  a = [1, 2, 3, 1]
  b = [1, 4]
  c = [1, 5]

  assert_equal [1, 2, 3, 4, 5], a.union(b,c)
end

assert("Array#&") do
  a = [1, 2, 3, 1]
  b = [1, 4]
  c = 1

  assert_raise(TypeError) { a & c }
  assert_equal [1], (a & b)
  assert_equal [1, 2, 3, 1], a
end

assert("Array#flatten") do
  assert_equal [1, 2, "3", {4=>5}, :'6'],    [1, 2, "3", {4=>5}, :'6'].flatten
  assert_equal [1, 2, 3, 4, 5, 6], [1, 2,    [3, 4, 5], 6].flatten
  assert_equal [1, 2, 3, 4, 5, 6], [1, 2,    [3, [4, 5], 6]].flatten
  assert_equal [1, [2, [3, [4, [5, [6]]]]]], [1, [2, [3, [4, [5, [6]]]]]].flatten(0)
  assert_equal [1, 2, [3, [4, [5, [6]]]]],   [1, [2, [3, [4, [5, [6]]]]]].flatten(1)
  assert_equal [1, 2, 3, [4, [5, [6]]]],     [1, [2, [3, [4, [5, [6]]]]]].flatten(2)
  assert_equal [1, 2, 3, 4, [5, [6]]],       [1, [2, [3, [4, [5, [6]]]]]].flatten(3)
  assert_equal [1, 2, 3, 4, 5, [6]],         [1, [2, [3, [4, [5, [6]]]]]].flatten(4)
  assert_equal [1, 2, 3, 4, 5, 6],           [1, [2, [3, [4, [5, [6]]]]]].flatten(5)
end

assert("Array#flatten!") do
  assert_equal [1, 2, 3, 4, 5, 6], [1, 2, [3, [4, 5], 6]].flatten!
end

assert("Array#compact") do
  a = [1, nil, "2", nil, :t, false, nil]
  assert_equal [1, "2", :t, false], a.compact
  assert_equal [1, nil, "2", nil, :t, false, nil], a
end

assert("Array#compact!") do
  a = [1, nil, "2", nil, :t, false, nil]
  a.compact!
  assert_equal [1, "2", :t, false], a
end

assert("Array#fetch") do
  a = [ 11, 22, 33, 44 ]
  assert_equal 22, a.fetch(1)
  assert_equal 44, a.fetch(-1)
  assert_equal 'cat', a.fetch(4, 'cat')
  ret = 0
  a.fetch(100) { |i| ret = i }
  assert_equal 100, ret
  assert_raise(IndexError) { a.fetch(100) }
end

assert("Array#fill") do
  a = [ "a", "b", "c", "d" ]
  assert_equal ["x", "x", "x", "x"], a.fill("x")
  assert_equal ["x", "x", "x", "w"], a.fill("w", -1)
  assert_equal ["x", "x", "z", "z"], a.fill("z", 2, 2)
  assert_equal ["y", "y", "z", "z"], a.fill("y", 0..1)
  assert_equal [0, 1, 4, 9], a.fill { |i| i*i }
  assert_equal [0, 1, 8, 27], a.fill(-2) { |i| i*i*i }
  assert_equal [0, 2, 3, 27], a.fill(1, 2) { |i| i+1 }
  assert_equal [1, 2, 3, 27], a.fill(0..1) { |i| i+1 }
  assert_raise(ArgumentError) { a.fill }

  assert_equal([0, 1, 2, 3, -1, 5], [0, 1, 2, 3, 4, 5].fill(-1, -2, 1))
  assert_equal([0, 1, 2, 3, -1, -1, -1], [0, 1, 2, 3, 4, 5].fill(-1, -2, 3))
  assert_equal([0, 1, 2, -1, -1, 5], [0, 1, 2, 3, 4, 5].fill(-1, 3..4))
  assert_equal([0, 1, 2, -1, 4, 5], [0, 1, 2, 3, 4, 5].fill(-1, 3...4))
  assert_equal([0, 1, -1, -1, -1, 5], [0, 1, 2, 3, 4, 5].fill(-1, 2..-2))
  assert_equal([0, 1, -1, -1, 4, 5], [0, 1, 2, 3, 4, 5].fill(-1, 2...-2))
  assert_equal([0, 1, 2, 13, 14, 5], [0, 1, 2, 3, 4, 5].fill(3..4){|i| i+10})
  assert_equal([0, 1, 2, 13, 4, 5], [0, 1, 2, 3, 4, 5].fill(3...4){|i| i+10})
  assert_equal([0, 1, 12, 13, 14, 5], [0, 1, 2, 3, 4, 5].fill(2..-2){|i| i+10})
  assert_equal([0, 1, 12, 13, 4, 5], [0, 1, 2, 3, 4, 5].fill(2...-2){|i| i+10})

  assert_equal [1, 2, 3, 4, 'x', 'x'], [1, 2, 3, 4, 5, 6].fill('x', -2..-1)
  assert_equal [1, 2, 3, 4, 'x', 6], [1, 2, 3, 4, 5, 6].fill('x', -2...-1)
  assert_equal [1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6].fill('x', -2...-2)
  assert_equal [1, 2, 3, 4, 'x', 6], [1, 2, 3, 4, 5, 6].fill('x', -2..-2)
  assert_equal [1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6].fill('x', -2..0)
end

assert("Array#reverse_each") do
  a = [ "a", "b", "c", "d" ]
  b = []
  a.reverse_each do |i|
    b << i
  end
  assert_equal [ "d", "c", "b", "a" ], b

  if Object.const_defined?(:Enumerator)
    assert_equal [ "d", "c", "b", "a" ], a.reverse_each.to_a
  else
    true
  end
end

assert("Array#rotate") do
  a = ["a", "b", "c", "d"]
  assert_equal ["b", "c", "d", "a"], a.rotate
  assert_equal ["a", "b", "c", "d"], a
  assert_equal ["c", "d", "a", "b"], a.rotate(2)
  assert_equal ["b", "c", "d", "a"], a.rotate(-3)
  assert_equal ["c", "d", "a", "b"], a.rotate(10)
  assert_equal [], [].rotate
end

assert("Array#rotate!") do
  a = ["a", "b", "c", "d"]
  assert_equal ["b", "c", "d", "a"], a.rotate!
  assert_equal ["b", "c", "d", "a"], a
  assert_equal ["d", "a", "b", "c"], a.rotate!(2)
  assert_equal ["a", "b", "c", "d"], a.rotate!(-3)
  assert_equal ["c", "d", "a", "b"], a.rotate(10)
  assert_equal [], [].rotate!
end

assert("Array#delete_if") do
  a = [1, 2, 3, 4, 5]
  assert_equal [1, 2, 3, 4, 5], a.delete_if { false }
  assert_equal [1, 2, 3, 4, 5], a

  a = [1, 2, 3, 4, 5]
  assert_equal [], a.delete_if { true }
  assert_equal [], a

  a = [1, 2, 3, 4, 5]
  assert_equal [1, 2, 3], a.delete_if { |i| i > 3 }
  assert_equal [1, 2, 3], a
end

assert("Array#reject!") do
  a = [1, 2, 3, 4, 5]
  assert_nil a.reject! { false }
  assert_equal [1, 2, 3, 4, 5], a

  a = [1, 2, 3, 4, 5]
  assert_equal [], a.reject! { true }
  assert_equal [], a

  a = [1, 2, 3, 4, 5]
  assert_equal [1, 2, 3], a.reject! { |val| val > 3 }
  assert_equal [1, 2, 3], a
end

assert("Array#insert") do
  a = ["a", "b", "c", "d"]
  assert_equal ["a", "b", 99, "c", "d"], a.insert(2, 99)
  assert_equal ["a", "b", 99, "c", 1, 2, 3, "d"], a.insert(-2, 1, 2, 3)

  b = ["a", "b", "c", "d"]
  assert_equal ["a", "b", "c", "d", nil, nil, 99], b.insert(6, 99)
end

assert("Array#bsearch") do
  # Find minimum mode
  a = [0, 2, 4]
  assert_equal 0, a.bsearch{ |x| x >= -1 }
  assert_equal 0, a.bsearch{ |x| x >= 0 }
  assert_equal 2, a.bsearch{ |x| x >= 1 }
  assert_equal 2, a.bsearch{ |x| x >= 2 }
  assert_equal 4, a.bsearch{ |x| x >= 3 }
  assert_equal 4, a.bsearch{ |x| x >= 4 }
  assert_nil      a.bsearch{ |x| x >= 5 }

  # Find any mode
  a = [0, 4, 8]
  def between(lo, x, hi)
    if x < lo
      1
    elsif x > hi
      -1
    else
      0
    end
  end
  assert_nil      a.bsearch{ |x| between(-3, x, -1) }
  assert_equal 0, a.bsearch{ |x| between(-1, x,  1) }
  assert_nil      a.bsearch{ |x| between( 1, x,  3) }
  assert_equal 4, a.bsearch{ |x| between( 3, x,  5) }
  assert_nil      a.bsearch{ |x| between( 5, x,  7) }
  assert_equal 8, a.bsearch{ |x| between( 7, x,  9) }
  assert_nil      a.bsearch{ |x| between( 9, x, 11) }

  assert_equal 0, a.bsearch{ |x| between( 0, x,  3) }
  assert_equal 4, a.bsearch{ |x| between( 0, x,  4) }
  assert_equal 4, a.bsearch{ |x| between( 4, x,  8) }
  assert_equal 8, a.bsearch{ |x| between( 5, x,  8) }

  # Invalid block result
  assert_raise TypeError, 'invalid block result (must be numeric, true, false or nil)' do
    a.bsearch{ 'I like to watch the world burn' }
  end
end

assert("Array#bsearch_index") do
  # tested through Array#bsearch
end

assert("Array#delete_if") do
  a = [1, 2, 3, 4, 5]
  assert_equal [1, 2, 3, 4, 5], a.delete_if { false }
  assert_equal [1, 2, 3, 4, 5], a

  a = [1, 2, 3, 4, 5]
  assert_equal [], a.delete_if { true }
  assert_equal [], a

  a = [ 1, 2, 3, 4, 5 ]
  assert_equal [1, 2, 3], a.delete_if { |val| val > 3 }
end

assert("Array#keep_if") do
  a = [1, 2, 3, 4, 5]
  assert_equal [1, 2, 3, 4, 5], a.keep_if { true }
  assert_equal [1, 2, 3, 4, 5], a

  a = [1, 2, 3, 4, 5]
  assert_equal [], a.keep_if { false }
  assert_equal [], a

  a = [1, 2, 3, 4, 5]
  assert_equal [4, 5], a.keep_if { |val| val > 3 }
  assert_equal [4, 5], a
end

assert("Array#select!") do
  a = [1, 2, 3, 4, 5]
  assert_nil a.select! { true }
  assert_equal [1, 2, 3, 4, 5], a

  a = [1, 2, 3, 4, 5]
  assert_equal [], a.select! { false }
  assert_equal [], a

  a = [1, 2, 3, 4, 5]
  assert_equal [4, 5], a.select! { |val| val > 3 }
  assert_equal [4, 5], a
end

assert('Array#values_at') do
  a = %w{red green purple white none}

  assert_equal %w{red purple none}, a.values_at(0, 2, 4)
  assert_equal ['green', 'white', nil, nil], a.values_at(1, 3, 5, 7)
  assert_equal ['none', 'white', 'white', nil], a.values_at(-1, -2, -2, -7)
  assert_equal ['none', nil, nil, 'red', 'green', 'purple'], a.values_at(4..6, 0...3)
  assert_raise(TypeError) { a.values_at 'tt' }
end

assert('Array#to_h') do
  assert_equal({}, [].to_h)
  assert_equal({a: 1, b:2}, [[:a, 1], [:b, 2]].to_h)

  assert_raise(TypeError)     { [1].to_h }
  assert_raise(ArgumentError) { [[1]].to_h }
end

assert("Array#index (block)") do
  assert_nil (1..10).to_a.index { |i| i % 5 == 0 and i % 7 == 0 }
  assert_equal 34, (1..100).to_a.index { |i| i % 5 == 0 and i % 7 == 0 }
end

assert("Array#dig") do
  h = [[[1]], 0]
  assert_equal(1, h.dig(0, 0, 0))
  assert_nil(h.dig(2, 0))
  assert_raise(TypeError) {h.dig(:a)}
end

assert("Array#slice!") do
  a = [1, 2, 3]
  b = a.slice!(0)
  c = [1, 2, 3, 4, 5]
  d = c.slice!(0, 2)
  e = [1, 2, 3, 4, 5]
  f = e.slice!(1..3)
  g = [1, 2, 3]
  h = g.slice!(-1)
  i = [1, 2, 3]
  j = i.slice!(0, -1)

  assert_equal(a, [2, 3])
  assert_equal(b, 1)
  assert_equal(c, [3, 4, 5])
  assert_equal(d, [1, 2])
  assert_equal(e, [1, 5])
  assert_equal(f, [2, 3, 4])
  assert_equal(g, [1, 2])
  assert_equal(h, 3)
  assert_equal(i, [1, 2, 3])
  assert_equal(j, nil)
end

assert("Array#permutation") do
  a = [1, 2, 3]
  assert_equal([[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]],
               a.permutation.to_a)
  assert_equal([[1],[2],[3]],
               a.permutation(1).to_a)
  assert_equal([[1,2],[1,3],[2,1],[2,3],[3,1],[3,2]],
               a.permutation(2).to_a)
  assert_equal([[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]],
               a.permutation(3).to_a)
  assert_equal([[]], a.permutation(0).to_a)
  assert_equal([], a.permutation(4).to_a)
end

assert("Array#combination") do
  a = [1, 2, 3, 4]
  assert_equal([[1],[2],[3],[4]],
               a.combination(1).to_a)
  assert_equal([[1,2],[1,3],[1,4],[2,3],[2,4],[3,4]],
               a.combination(2).to_a)
  assert_equal([[1,2,3],[1,2,4],[1,3,4],[2,3,4]],
               a.combination(3).to_a)
  assert_equal([[1,2,3,4]],
               a.combination(4).to_a)
  assert_equal([[]], a.combination(0).to_a)
  assert_equal([], a.combination(5).to_a)
end

assert('Array#transpose') do
  assert_equal([].transpose, [])
  assert_equal([[]].transpose, [])
  assert_equal([[1]].transpose, [[1]])
  assert_equal([[1,2,3]].transpose, [[1], [2], [3]])
  assert_equal([[1], [2], [3]].transpose, [[1,2,3]])
  assert_equal([[1,2], [3,4], [5,6]].transpose, [[1,3,5], [2,4,6]])
  assert_raise(TypeError) { [1].transpose }
  assert_raise(IndexError) { [[1], [2,3,4]].transpose }
end
