##
# Random Test

assert("Random#srand") do
  r1 = Random.new(123)
  r2 = Random.new(123)
  r1.rand == r2.rand
end

assert("Kernel::srand") do
  srand(234)
  r1 = rand
  srand(234)
  r2 = rand
  r1 == r2
end

assert("Random::srand") do
  Random.srand(345)
  r1 = rand
  srand(345)
  r2 = Random.rand
  r1 == r2
end

assert("fixnum") do
  rand(3).class == Fixnum
end

assert("float") do
  rand.class == Float
end

assert("Array#shuffle") do
  ary = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  shuffled = ary.shuffle

  ary == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] and shuffled != ary and 10.times { |x| ary.include? x }
end

assert('Array#shuffle!') do
  ary = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  ary.shuffle!

  ary != [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] and 10.times { |x| ary.include? x }
end

assert("Array#shuffle(random)") do
  assert_raise(TypeError) do
    # this will cause an exception due to the wrong argument
    [1, 2].shuffle "Not a Random instance"
  end

  # verify that the same seed causes the same results
  ary1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  shuffle1 = ary1.shuffle Random.new 345
  ary2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  shuffle2 = ary2.shuffle Random.new 345

  ary1 != shuffle1 and 10.times { |x| shuffle1.include? x } and shuffle1 == shuffle2
end

assert('Array#shuffle!(random)') do
  assert_raise(TypeError) do
    # this will cause an exception due to the wrong argument
    [1, 2].shuffle! "Not a Random instance"
  end

  # verify that the same seed causes the same results
  ary1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  ary1.shuffle! Random.new 345
  ary2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  ary2.shuffle! Random.new 345

  ary1 != [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] and 10.times { |x| ary1.include? x } and ary1 == ary2
end

assert('Array#sample checks input length after reading arguments') do
  $ary = [1, 2, 3]
  class ArrayChange
    def to_i
      $ary << 4
      4
    end
  end

  assert_equal [1, 2, 3, 4], $ary.sample(ArrayChange.new).sort
end
