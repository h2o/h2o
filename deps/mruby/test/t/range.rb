##
# Range ISO Test

assert('Range', '15.2.14') do
  assert_equal Class, Range.class
end

assert('Range#==', '15.2.14.4.1') do
  assert_true (1..10) == (1..10)
  assert_false (1..10) == (1..100)
  assert_false (1..10) == (1..)
  assert_false (1..10) == (..10)

  assert_true (1..) == (1..nil)
  assert_true (1..) == (1..)
  assert_false (1..) == (1...)

  assert_true (..1) == (nil..1)
  assert_true (..1) == (..1)
  assert_false (..1) == (...1)

  skip unless Object.const_defined?(:Float)
  assert_true (1..10) == Range.new(1.0, 10.0)

end

assert('Range#===', '15.2.14.4.2') do
  a = (1..10)
  b = (1..)
  c = (..10)

  assert_true a === 5
  assert_false a === 20
  assert_true b === 20
  assert_false b === 0
  assert_false c === 20
  assert_true c === 0
end

assert('Range#begin', '15.2.14.4.3') do
  assert_equal 1, (1..10).begin
  assert_equal 1, (1..).begin
  assert_nil (..1).begin
end

assert('Range#each', '15.2.14.4.4') do
  a = (1..3)
  b = 0
  a.each {|i| b += i}
  assert_equal 6, b
  c = []
  (1..).each { |i| c << i; break if c.size == 10 }
  assert_equal [1, 2, 3, 4, 5, 6, 7, 8 ,9, 10], c
end

assert('Range#end', '15.2.14.4.5') do
  assert_equal 10, (1..10).end
  assert_nil (1..).end
  assert_equal 10, (..10).end
end

assert('Range#exclude_end?', '15.2.14.4.6') do
  assert_true (1...10).exclude_end?
  assert_false (1..10).exclude_end?
  assert_true (1...).exclude_end?
  assert_false (1..).exclude_end?
  assert_true (...1).exclude_end?
  assert_false (..1).exclude_end?
end

assert('Range#first', '15.2.14.4.7') do
  assert_equal 1, (1..10).first
  assert_equal 1, (1..).first
end

assert('Range#include?', '15.2.14.4.8') do
  assert_true (1..10).include?(10)
  assert_false (1..10).include?(11)
  assert_true (1..).include?(10)
  assert_false (1..).include?(0)
  assert_true (..10).include?(10)
  assert_true (..10).include?(0)

  assert_true (1...10).include?(9)
  assert_false (1...10).include?(10)
  assert_true (1...).include?(10)
  assert_false (1...).include?(0)
  assert_false (...10).include?(10)
  assert_true (...10).include?(0)
end

assert('Range#initialize', '15.2.14.4.9') do
  a = Range.new(1, 10, true)
  b = Range.new(1, 10, false)

  assert_equal (1...10), a
  assert_true a.exclude_end?
  assert_equal (1..10), b
  assert_false b.exclude_end?

  assert_raise(NameError) { (0..1).__send__(:initialize, 1, 3) }

  c = Range.new(1, nil, true)
  d = Range.new(1, nil, false)

  assert_equal (1...nil), c
  assert_true c.exclude_end?
  assert_equal (1..nil), d
  assert_false d.exclude_end?
end

assert('Range#last', '15.2.14.4.10') do
  assert_equal 10, (1..10).last
  assert_nil (1..).last
end

assert('Range#member?', '15.2.14.4.11') do
  a = (1..10)
  b = (1..)

  assert_true a.member?(5)
  assert_false a.member?(20)
  assert_true b.member?(20)
  assert_false b.member?(0)
end

assert('Range#to_s', '15.2.14.4.12') do
  assert_equal "0..1", (0..1).to_s
  assert_equal "0...1", (0...1).to_s
  assert_equal "a..b", ("a".."b").to_s
  assert_equal "a...b", ("a"..."b").to_s
  assert_equal "0..", (0..).to_s
  assert_equal "0...", (0...).to_s
  assert_equal "a..", ("a"..).to_s
  assert_equal "a...", ("a"...).to_s
end

assert('Range#inspect', '15.2.14.4.13') do
  assert_equal "0..1", (0..1).inspect
  assert_equal "0...1", (0...1).inspect
  assert_equal "\"a\"..\"b\"", ("a".."b").inspect
  assert_equal "\"a\"...\"b\"", ("a"..."b").inspect
  assert_equal "0..", (0..).inspect
  assert_equal "0...", (0...).inspect
  assert_equal "\"a\"..", ("a"..).inspect
  assert_equal "\"a\"...", ("a"...).inspect
end

assert('Range#eql?', '15.2.14.4.14') do
  assert_true (1..10).eql? (1..10)
  assert_false (1..10).eql? (1..100)
  assert_false (1..10).eql? "1..10"
  assert_true (1..).eql? (1..)
  assert_false (1..).eql? (2..)
  assert_false (1..).eql? "1.."
  skip unless Object.const_defined?(:Float)
  assert_false (1..10).eql? (Range.new(1.0, 10.0))
  assert_false (1..).eql? (Range.new(1.0, nil))
end

assert('Range#initialize_copy', '15.2.14.4.15') do
  assert_raise(NameError) { (0..1).__send__(:initialize_copy, 1..3) }
end

assert('Range#hash', '15.3.1.3.15') do
  assert_kind_of(Integer, (1..10).hash)
  assert_equal (1..10).hash, (1..10).hash
  assert_not_equal (1..10).hash, (1...10).hash
  assert_equal (1..).hash, (1..).hash
  assert_not_equal (1..).hash, (1...).hash
end

assert('Range#dup') do
  r = (1..3).dup
  assert_equal 1, r.begin
  assert_equal 3, r.end
  assert_false r.exclude_end?

  r = ("a"..."z").dup
  assert_equal "a", r.begin
  assert_equal "z", r.end
  assert_true r.exclude_end?

  r = (1..).dup
  assert_equal 1, r.begin
  assert_nil r.end
  assert_false r.exclude_end?
end

assert('Range#to_a') do
  assert_equal([1, 2, 3, 4, 5], (1..5).to_a)
  assert_equal([1, 2, 3, 4], (1...5).to_a)
  assert_raise(RangeError) { (1..).to_a }
end
