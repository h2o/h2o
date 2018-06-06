##
# Enumerable(Ext) Test

assert("Enumerable#drop") do
  a = [1, 2, 3, 4, 5, 0]

  assert_equal [4, 5, 0], a.drop(3)
  assert_equal [], a.drop(6)
end

assert("Enumerable#drop_while") do
  a = [1, 2, 3, 4, 5, 0]
  assert_equal [3, 4, 5, 0], a.drop_while {|i| i < 3 }
end

assert("Enumerable#take") do
  a = [1, 2, 3, 4, 5, 0]
  assert_equal [1, 2, 3], a.take(3)
end

assert("Enumerable#take_while") do
  a = [1, 2, 3, 4, 5, 0]
  assert_equal [1, 2], a.take_while {|i| i < 3}
end

assert("Enumerable#each_cons") do
  a = []
  b = (1..5).each_cons(3){|e| a << e}
  assert_equal [[1, 2, 3], [2, 3, 4], [3, 4, 5]], a
  assert_equal nil, b
end

assert("Enumerable#each_slice") do
  a = []
  b = (1..10).each_slice(3){|e| a << e}
  assert_equal [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]], a
  assert_equal nil, b
end

assert("Enumerable#group_by") do
  r = (1..6).group_by {|i| i % 3 }
  assert_equal [3, 6], r[0]
  assert_equal [1, 4], r[1]
  assert_equal [2, 5], r[2]
end

assert("Enumerable#sort_by") do
  assert_equal ["car", "train", "bicycle"], %w{car bicycle train}.sort_by {|e| e.length}
end

assert("Enumerable#first") do
  a = Object.new
  a.extend Enumerable
  def a.each
    yield 1
    yield 2
    yield 3
  end
  assert_equal 1, a.first
  assert_equal [1, 2], a.first(2)
  assert_equal [1, 2, 3], a.first(10)
  a = Object.new
  a.extend Enumerable
  def a.each
  end
  assert_nil a.first
end

assert("Enumerable#count") do
  a = [1, 2, 4, 2]
  assert_equal 4, a.count
  assert_equal 2, a.count(2)
  assert_equal 3, a.count{|x| x % 2 == 0}
end

assert("Enumerable#flat_map") do
  assert_equal [1, 2, 3, 4], [1, 2, 3, 4].flat_map { |e| e }
  assert_equal [1, -1, 2, -2, 3, -3, 4, -4], [1, 2, 3, 4].flat_map { |e| [e, -e] }
  assert_equal [1, 2, 100, 3, 4, 100], [[1, 2], [3, 4]].flat_map { |e| e + [100] }
end

assert("Enumerable#max_by") do
  assert_equal "albatross", %w[albatross dog horse].max_by { |x| x.length }
end

assert("Enumerable#min_by") do
  assert_equal "dog", %w[albatross dog horse].min_by { |x| x.length }
end

assert("Enumerable#minmax") do
  a = %w(albatross dog horse)
  assert_equal ["albatross", "horse"], a.minmax
  assert_equal ["dog", "albatross"], a.minmax { |a, b| a.length <=> b.length }
end

assert("Enumerable#minmax_by") do
  assert_equal ["dog", "albatross"], %w(albatross dog horse).minmax_by { |x| x.length }
end

assert("Enumerable#none?") do
  assert_true %w(ant bear cat).none? { |word| word.length == 5 }
  assert_false %w(ant bear cat).none? { |word| word.length >= 4 }
  assert_false [1, 3.14, 42].none?(Float)
  assert_true [].none?
  assert_true [nil, false].none?
  assert_false [nil, true].none?
end

assert("Enumerable#one?") do
  assert_true %w(ant bear cat).one? { |word| word.length == 4 }
  assert_false %w(ant bear cat).one? { |word| word.length > 4 }
  assert_false %w(ant bear cat).one? { |word| word.length < 4 }
  assert_true [1, 3.14, 42].one?(Float)
  assert_false [nil, true, 99].one?
  assert_true [nil, true, false].one?
  assert_true [ nil, true, 99 ].one?(Integer)
  assert_false [].one?
end

assert("Enumerable#all? (enhancement)") do
  assert_false [1, 2, 3.14].all?(Integer)
  assert_true [1, 2, 3.14].all?(Numeric)
end

assert("Enumerable#any? (enhancement)") do
  assert_false [1, 2, 3].all?(Float)
  assert_true [nil, true, 99].any?(Integer)
end

assert("Enumerable#each_with_object") do
  assert_true [2, 4, 6, 8, 10, 12, 14, 16, 18, 20], (1..10).each_with_object([]) { |i, a| a << i*2 }
  assert_raise(ArgumentError) { (1..10).each_with_object() { |i, a| a << i*2 } }
end

assert("Enumerable#reverse_each") do
  r = (1..3)
  a = []
  assert_equal (1..3), r.reverse_each { |v| a << v }
  assert_equal [3, 2, 1], a
end

assert("Enumerable#cycle") do
  a = []
  ["a", "b", "c"].cycle(2) { |v| a << v }
  assert_equal ["a", "b", "c", "a", "b", "c"], a
  assert_raise(TypeError) { ["a", "b", "c"].cycle("a") { |v| a << v } }

  empty = Class.new do
    include Enumerable
    def each
    end
  end
  assert_nil empty.new.cycle { break :nope }
end

assert("Enumerable#find_index") do
  assert_nil (1..10).find_index { |i| i % 5 == 0 and i % 7 == 0 }
  assert_equal 34, (1..100).find_index { |i| i % 5 == 0 and i % 7 == 0 }
  assert_equal 49 ,(1..100).find_index(50)
end

assert("Enumerable#zip") do
  a = [ 4, 5, 6 ]
  b = [ 7, 8, 9 ]
  assert_equal [[4, 7], [5, 8], [6, 9]], a.zip(b)
  assert_equal [[1, 4, 7], [2, 5, 8], [3, 6, 9]], [1, 2, 3].zip(a, b)
  assert_equal [[1, 4, 7], [2, 5, 8]], [1, 2].zip(a, b)
  assert_equal [[4, 1, 8], [5, 2, nil], [6, nil, nil]], a.zip([1, 2], [8])

  ret = []
  assert_equal nil, a.zip([1, 2], [8]) { |i| ret << i }
  assert_equal [[4, 1, 8], [5, 2, nil], [6, nil, nil]], ret

  assert_raise(TypeError) { [1].zip(1) }
end

assert("Enumerable#to_h") do
  c = Class.new {
    include Enumerable
    def each
      yield [1,2]
      yield [3,4]
    end
  }
  h0 = {1=>2, 3=>4}
  h = c.new.to_h
  assert_equal Hash, h.class
  assert_equal h0, h
  # mruby-enum-ext also provides nil.to_h
  assert_equal Hash.new, nil.to_h
end
