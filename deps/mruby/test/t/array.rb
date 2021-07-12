##
# Array ISO Test

assert('Array', '15.2.12') do
  assert_equal(Class, Array.class)
end

assert('Array inclueded modules', '15.2.12.3') do
  assert_true(Array.include?(Enumerable))
end

assert('Array.[]', '15.2.12.4.1') do
  assert_equal([1, 2, 3], Array.[](1,2,3))
end

class SubArray < Array
end

assert('SubArray.[]') do
  a = SubArray[1, 2, 3]
  assert_equal(SubArray, a.class)
end

assert('Array#+', '15.2.12.5.1') do
  assert_equal([1, 1], [1].+([1]))
end

assert('Array#*', '15.2.12.5.2') do
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong argument
    [1].*(-1)
  end
  assert_equal([1, 1, 1], [1].*(3))
  assert_equal([], [1].*(0))
end

assert('Array#<<', '15.2.12.5.3') do
  assert_equal([1, 1], [1].<<(1))
end

assert('Array#[]', '15.2.12.5.4') do
  a = Array.new
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong arguments
    a.[]()
  end
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong arguments
    a.[](1,2,3)
  end

  assert_equal(2, [1,2,3].[](1))
  assert_equal(nil, [1,2,3].[](4))
  assert_equal(3, [1,2,3].[](-1))
  assert_equal(nil, [1,2,3].[](-4))

  a = [ "a", "b", "c", "d", "e" ]
  assert_equal(["b", "c"], a[1,2])
  assert_equal(["b", "c", "d"], a[1..-2])
  skip unless Object.const_defined?(:Float)
  assert_equal("b", a[1.1])
end

assert('Array#[]=', '15.2.12.5.5') do
  a = Array.new
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong arguments
    a.[]=()
  end
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong arguments
    a.[]=(1,2,3,4)
  end
  assert_raise(IndexError) do
    # this will cause an exception due to the wrong arguments
    a = [1,2,3,4,5]
    a[1, -1] = 10
  end

  assert_equal(4, [1,2,3].[]=(1,4))
  assert_equal(3, [1,2,3].[]=(1,2,3))

  a = [1,2,3,4,5]
  a[3..-1] = 6
  assert_equal([1,2,3,6], a)

  a = [1,2,3,4,5]
  a[3..-1] = []
  assert_equal([1,2,3], a)

  a = [1,2,3,4,5]
  a[2...4] = 6
  assert_equal([1,2,6,5], a)

  # passing self (#3274)
  a = [1,2,3]
  a[1,0] = a
  assert_equal([1,1,2,3,2,3], a)
  a = [1,2,3]
  a[-1,0] = a
  assert_equal([1,2,1,2,3,3], a)
end

assert('Array#clear', '15.2.12.5.6') do
  a = [1]
  a.clear
  assert_equal([], a)
end

assert('Array#collect!', '15.2.12.5.7') do
  a = [1,2,3]
  a.collect! { |i| i + i }
  assert_equal([2,4,6], a)
end

assert('Array#concat', '15.2.12.5.8') do
  assert_equal([1,2,3,4], [1, 2].concat([3, 4]))

  # passing self (#3302)
  a = [1,2,3]
  a.concat(a)
  assert_equal([1,2,3,1,2,3], a)
end

assert('Array#delete_at', '15.2.12.5.9') do
  a = [1,2,3]
  assert_equal(2, a.delete_at(1))
  assert_equal([1,3], a)
  assert_equal(nil, a.delete_at(3))
  assert_equal([1,3], a)
  assert_equal(nil, a.delete_at(-3))
  assert_equal([1,3], a)
  assert_equal(3, a.delete_at(-1))
  assert_equal([1], a)
end

assert('Array#each', '15.2.12.5.10') do
  a = [1,2,3]
  b = 0
  a.each {|i| b += i}
  assert_equal(6, b)
end

assert('Array#each_index', '15.2.12.5.11') do
  a = [1]
  b = nil
  a.each_index {|i| b = i}
  assert_equal(0, b)
end

assert('Array#empty?', '15.2.12.5.12') do
  a = []
  b = [b]
  assert_true([].empty?)
  assert_false([1].empty?)
end

assert('Array#first', '15.2.12.5.13') do
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong argument
    [1,2,3].first(-1)
  end
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong argument
    [1,2,3].first(1,2)
  end

  assert_nil([].first)

  b = [1,2,3]
  assert_equal(1, b.first)
  assert_equal([], b.first(0))
  assert_equal([1], b.first(1))
  assert_equal([1,2,3], b.first(4))
end

assert('Array#index', '15.2.12.5.14') do
  a = [1,2,3]

  assert_equal(1, a.index(2))
  assert_equal(nil, a.index(0))
end

assert('Array#initialize', '15.2.12.5.15') do
  a = [].initialize(1)
  b = [].initialize(2)
  c = [].initialize(2, 1)
  d = [].initialize(2) {|i| i}

  assert_equal([nil], a)
  assert_equal([nil,nil], b)
  assert_equal([1,1], c)
  assert_equal([0,1], d)
end

assert('Array#initialize_copy', '15.2.12.5.16') do
  a = [1,2,3]
  b = [].initialize_copy(a)

  assert_equal([1,2,3], b)
end

assert('Array#join', '15.2.12.5.17') do
  a = [1,2,3].join
  b = [1,2,3].join(',')

  assert_equal('123', a)
  assert_equal('1,2,3', b)
end

assert('Array#last', '15.2.12.5.18') do
  assert_raise(ArgumentError) do
    # this will cause an exception due to the wrong argument
    [1,2,3].last(-1)
  end

  a = [1,2,3]
  assert_equal(3, a.last)
  assert_nil([].last)
end

assert('Array#length', '15.2.12.5.19') do
  a = [1,2,3]

  assert_equal(3, a.length)
end

assert('Array#map!', '15.2.12.5.20') do
  a = [1,2,3]
  a.map! { |i| i + i }
  assert_equal([2,4,6], a)
end

assert('Array#pop', '15.2.12.5.21') do
  a = [1,2,3]
  b = a.pop

  assert_nil([].pop)
  assert_equal([1,2], a)
  assert_equal(3, b)

  assert_raise(FrozenError) { [].freeze.pop }
end

assert('Array#push', '15.2.12.5.22') do
  a = [1,2,3]
  b = a.push(4)

  assert_equal([1,2,3,4], a)
  assert_equal([1,2,3,4], b)
end

assert('Array#replace', '15.2.12.5.23') do
  a = [1,2,3]
  b = [].replace(a)

  assert_equal([1,2,3], b)
end

assert('Array#reverse', '15.2.12.5.24') do
  a = [1,2,3]
  b = a.reverse

  assert_equal([1,2,3], a)
  assert_equal([3,2,1], b)
end

assert('Array#reverse!', '15.2.12.5.25') do
  a = [1,2,3]
  b = a.reverse!

  assert_equal([3,2,1], a)
  assert_equal([3,2,1], b)
end

assert('Array#rindex', '15.2.12.5.26') do
  a = [1,2,3]

  assert_equal(1, a.rindex(2))
  assert_equal(nil, a.rindex(0))
end

assert('Array#shift', '15.2.12.5.27') do
  a = [1,2,3]
  b = a.shift

  assert_nil([].shift)
  assert_equal([2,3], a)
  assert_equal(1, b)

  assert_raise(FrozenError) { [].freeze.shift }
end

assert('Array#size', '15.2.12.5.28') do
  a = [1,2,3]

  assert_equal(3, a.size)
end

assert('Array#slice', '15.2.12.5.29') do
  a = [*(1..100)]
  b = a.dup

  assert_equal(1, a.slice(0))
  assert_equal(100, a.slice(99))
  assert_nil(a.slice(100))
  assert_equal(100, a.slice(-1))
  assert_equal(99,  a.slice(-2))
  assert_equal(1,   a.slice(-100))
  assert_nil(a.slice(-101))
  assert_equal([1],   a.slice(0,1))
  assert_equal([100], a.slice(99,1))
  assert_equal([],    a.slice(100,1))
  assert_equal([100], a.slice(99,100))
  assert_equal([100], a.slice(-1,1))
  assert_equal([99],  a.slice(-2,1))
  assert_equal([10, 11, 12], a.slice(9, 3))
  assert_equal([10, 11, 12], a.slice(-91, 3))
  assert_nil(a.slice(-101, 2))
  assert_equal([1],   a.slice(0..0))
  assert_equal([100], a.slice(99..99))
  assert_equal([],    a.slice(100..100))
  assert_equal([100], a.slice(99..200))
  assert_equal([100], a.slice(-1..-1))
  assert_equal([99],  a.slice(-2..-2))
  assert_equal([10, 11, 12], a.slice(9..11))
  assert_equal([10, 11, 12], a.slice(-91..-89))
  assert_equal([10, 11, 12], a.slice(-91..-89))
  assert_nil(a.slice(-101..-1))
  assert_nil(a.slice(10, -3))
  assert_equal([], a.slice(10..7))
  assert_equal(b, a)
end

assert('Array#unshift', '15.2.12.5.30') do
  a = [2,3]
  b = a.unshift(1)
  c = [2,3]
  d = c.unshift(0, 1)

  assert_equal([1,2,3], a)
  assert_equal([1,2,3], b)
  assert_equal([0,1,2,3], c)
  assert_equal([0,1,2,3], d)
end

assert('Array#to_s', '15.2.12.5.31 / 15.2.12.5.32') do
  a = [2, 3,   4, 5]
  a[4] = a
  r1 = a.to_s
  r2 = a.inspect

  assert_equal(r2, r1)
  assert_equal("[2, 3, 4, 5, [...]]", r1)
end

assert('Array#==', '15.2.12.5.33') do
  assert_false(["a", "c"] == ["a", "c", 7])
  assert_true(["a", "c", 7] == ["a", "c", 7])
  assert_false(["a", "c", 7] == ["a", "d", "f"])
end

assert('Array#eql?', '15.2.12.5.34') do
  a1 = [ 1, 2, 3 ]
  a2 = [ 1, 2, 3 ]
  a3 = [ 1.0, 2.0, 3.0 ]

  assert_true(a1.eql? a2)
  assert_false(a1.eql? a3)
end

assert('Array#hash', '15.2.12.5.35') do
  a = [ 1, 2, 3 ]

  #assert_true(a.hash.is_a? Integer)
  assert_true(a.hash.is_a? Integral)  # mruby special
  assert_equal([1,2].hash, [1,2].hash)
end

assert('Array#<=>', '15.2.12.5.36') do
  r1 = [ "a", "a", "c" ]    <=> [ "a", "b", "c" ]   #=> -1
  r2 = [ 1, 2, 3, 4, 5, 6 ] <=> [ 1, 2 ]            #=> +1
  r3 = [ "a", "b", "c" ]    <=> [ "a", "b", "c" ]   #=> 0

  assert_equal(-1, r1)
  assert_equal(+1, r2)
  assert_equal(0, r3)
end

# Not ISO specified

assert("Array (Longish inline array)") do
  ary = [[0, 0], [1, 1], [2, 2], [3, 3], [4, 4], [5, 5], [6, 6], [7, 7], [8, 8], [9, 9], [10, 10], [11, 11], [12, 12], [13, 13], [14, 14], [15, 15], [16, 16], [17, 17], [18, 18], [19, 19], [20, 20], [21, 21], [22, 22], [23, 23], [24, 24], [25, 25], [26, 26], [27, 27], [28, 28], [29, 29], [30, 30], [31, 31], [32, 32], [33, 33], [34, 34], [35, 35], [36, 36], [37, 37], [38, 38], [39, 39], [40, 40], [41, 41], [42, 42], [43, 43], [44, 44], [45, 45], [46, 46], [47, 47], [48, 48], [49, 49], [50, 50], [51, 51], [52, 52], [53, 53], [54, 54], [55, 55], [56, 56], [57, 57], [58, 58], [59, 59], [60, 60], [61, 61], [62, 62], [63, 63], [64, 64], [65, 65], [66, 66], [67, 67], [68, 68], [69, 69], [70, 70], [71, 71], [72, 72], [73, 73], [74, 74], [75, 75], [76, 76], [77, 77], [78, 78], [79, 79], [80, 80], [81, 81], [82, 82], [83, 83], [84, 84], [85, 85], [86, 86], [87, 87], [88, 88], [89, 89], [90, 90], [91, 91], [92, 92], [93, 93], [94, 94], [95, 95], [96, 96], [97, 97], [98, 98], [99, 99], [100, 100], [101, 101], [102, 102], [103, 103], [104, 104], [105, 105], [106, 106], [107, 107], [108, 108], [109, 109], [110, 110], [111, 111], [112, 112], [113, 113], [114, 114], [115, 115], [116, 116], [117, 117], [118, 118], [119, 119], [120, 120], [121, 121], [122, 122], [123, 123], [124, 124], [125, 125], [126, 126], [127, 127], [128, 128], [129, 129], [130, 130], [131, 131], [132, 132], [133, 133], [134, 134], [135, 135], [136, 136], [137, 137], [138, 138], [139, 139], [140, 140], [141, 141], [142, 142], [143, 143], [144, 144], [145, 145], [146, 146], [147, 147], [148, 148], [149, 149], [150, 150], [151, 151], [152, 152], [153, 153], [154, 154], [155, 155], [156, 156], [157, 157], [158, 158], [159, 159], [160, 160], [161, 161], [162, 162], [163, 163], [164, 164], [165, 165], [166, 166], [167, 167], [168, 168], [169, 169], [170, 170], [171, 171], [172, 172], [173, 173], [174, 174], [175, 175], [176, 176], [177, 177], [178, 178], [179, 179], [180, 180], [181, 181], [182, 182], [183, 183], [184, 184], [185, 185], [186, 186], [187, 187], [188, 188], [189, 189], [190, 190], [191, 191], [192, 192], [193, 193], [194, 194], [195, 195], [196, 196], [197, 197], [198, 198], [199, 199]]
  h = Hash.new(0)
  ary.each {|p| h[p.class] += 1}
  assert_equal({Array=>200}, h)
end

assert("Array#rindex") do
  class Sneaky
    def ==(*)
      $a.clear
      $a.replace([1])
      false
    end
  end
  $a = [2, 3, 4, 5, 6, 7, 8, 9, 10, Sneaky.new]
  assert_equal 0, $a.rindex(1)
end

assert('Array#sort!') do
  a = [3, 2, 1]
  assert_equal a, a.sort!      # sort! returns self.
  assert_equal [1, 2, 3], a    # it is sorted.
end

assert('Array#freeze') do
  a = [].freeze
  assert_raise(FrozenError) do
    a[0] = 1
  end
end
