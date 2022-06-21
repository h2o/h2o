##
# Hash ISO Test

class HashKey
  attr_accessor :value, :error, :callback

  self.class.alias_method :[], :new

  def initialize(value, error: nil, callback: nil)
    @value = value
    @error = error
    @callback = callback
  end

  def ==(other)
    @callback.(:==, self, other) if @callback
    return raise_error(:==) if @error == true || @error == :==
    other.kind_of?(self.class) && @value == other.value
  end

  def eql?(other)
    @callback.(:eql?, self, other) if @callback
    return raise_error(:eql?) if @error == true || @error == :eql?
    other.kind_of?(self.class) && @value.eql?(other.value)
  end

  def hash
    @callback.(:hash, self) if @callback
    return raise_error(:hash) if @error == true || @error == :hash
    @value % 3
  end

  def to_s
    "#{self.class}[#{@value}]"
  end
  alias inspect to_s

  def raise_error(name)
    raise "##{self}: #{name} error"
  end
end

class HashEntries < Array
  self.class.alias_method :[], :new

  def initialize(entries) self.replace(entries) end
  def key(index, k=get=true) get ? self[index][0] : (self[index][0] = k) end
  def value(index, v=get=true) get ? self[index][1] : (self[index][1] = v) end
  def keys; map{|k, v| k} end
  def values; map{|k, v| v} end
  def each_key(&block) each{|k, v| block.(k)} end
  def each_value(&block) each{|k, v| block.(v)} end
  def dup2; self.class[*map{|k, v| [k.dup, v.dup]}] end
  def to_s; "#{self.class}#{super}" end
  alias inspect to_s

  def hash_for(hash={}, &block)
    each{|k, v| hash[k] = v}
    block.(hash) if block
    hash
  end
end

def ar_entries
  HashEntries[
    [1, "one"],
    [HashKey[2], :two],
    [nil, :two],
    [:one, 1],
    ["&", "&amp;"],
    [HashKey[6], :six],
    [HashKey[5], :five],  # same hash code as HashKey[2]
  ]
end

def ht_entries
  ar_entries.dup.push(
    ["id", 32],
    [:date, "2020-05-02"],
    [200, "OK"],
    ["modifiers", ["left_shift", "control"]],
    [:banana, :yellow],
    ["JSON", "JavaScript Object Notation"],
    [:size, :large],
    ["key_code", "h"],
    ["h", 0x04],
    [[3, 2, 1], "three, two, one"],
    [:auto, true],
    [HashKey[12], "December"],
    [:path, "/path/to/file"],
    [:name, "Ruby"],
  )
end

def merge_entries!(entries1, entries2)
  entries2.each do |k2, v2|
    entry1 = entries1.find{|k1, _| k1.eql?(k2)}
    entry1 ? (entry1[1] = v2) : (entries1 << [k2, v2])
  end
  entries1
end

def product(*arrays, &block)
  sizes = Array.new(arrays.size+1, 1)
  (arrays.size-1).downto(0){|i| sizes[i] = arrays[i].size * sizes[i+1]}
  size = sizes[0]
  results = Array.new(size){[]}
  arrays.each_with_index do |array, arrays_i|
    results_i = -1
    (size / sizes[arrays_i]).times do
      array.each do |v|
        sizes[arrays_i+1].times{results[results_i+=1] << v}
      end
    end
  end
  results.each{block.(_1)}
end

def assert_iterator(exp, obj, meth)
  params = []
  obj.__send__(meth) {|param| params << param}
  assert_equal(exp, params)
end

def assert_nothing_crashed(&block)
  block.call rescue nil
  pass
end

assert('Hash', '15.2.13') do
  assert_equal(Class, Hash.class)
end

[[:==, '15.2.13.4.1'], [:eql?, '']].each do |meth, iso|
  assert("Hash##{meth}", iso) do
    cls = Class.new(Hash){attr_accessor :foo}
    [ar_entries, ht_entries].each do |entries|
      h1 = entries.hash_for
      h2 = entries.dup.reverse!.hash_for
      assert_operator(h1, meth, h2)
      assert_operator(h1, meth, h1)
      assert_not_operator(h1, meth, true)
      assert_operator({}, meth, Hash.new)

      h1 = entries.hash_for(cls.new(1)) {|h| h.foo = 1}
      h2 = entries.hash_for(cls.new(2)) {|h| h.foo = 2}
      assert_operator(h1, meth, h2)

      h1 = entries.hash_for
      h2 = entries.hash_for(cls.new)
      assert_operator(h1, meth, h2)

      h1 = (entries.dup << [:_k, 1]).hash_for
      h2 = (entries.dup << [:_k, 2]).hash_for
      assert_not_operator(h1, meth, h2)

      h1 = (entries.dup << [:_k1, 0]).hash_for
      h2 = (entries.dup << [:_k2, 0]).hash_for
      assert_not_operator(h1, meth, h2)

      h1 = entries.hash_for
      h2 = (entries.dup << [:_k, 2]).hash_for
      assert_not_operator(h1, meth, h2)

      k1, v1 = HashKey[-1], HashKey[-2]
      k2, v2 = HashKey[-1], HashKey[-2]
      h1 = (entries.dup << [k1, v1]).hash_for
      h2 = (entries.dup << [k2, v2]).hash_for
      product([h1, h2], [k1, k2], %i[eql? hash]) do |h, k, m|
        [k1, k2].each{_1.callback = nil}
        k.callback = ->(name, *){h.clear if name == m}
        assert_nothing_crashed{h1.__send__(meth, h2)}
      end
      product([h1, h2], [v1, v2]) do |h, v|
        [v1, v2].each{_1.callback = nil}
        v.callback = ->(name, *){h.clear if name == meth}
        assert_nothing_crashed{h1.__send__(meth, h2)}
      end

      if Object.const_defined?(:Float)
        h1 = (entries.dup << [-1, true]).hash_for
        h2 = (entries.dup << [-1.0, true]).hash_for
        assert_not_operator(h1, meth, h2)
        h1 = (entries.dup << [-1.0, true]).hash_for
        h2 = (entries.dup << [-1, true]).hash_for
        assert_not_operator(h1, meth, h2)

        h1 = (entries.dup << [:_k, 1]).hash_for
        h2 = (entries.dup << [:_k, 1.0]).hash_for
        if meth == :==
          assert_operator(h1, meth, h2)
        else
          assert_not_operator(h1, meth, h2)
        end
      end
    end
  end
end

assert('Hash#[]', '15.2.13.4.2') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for
    assert_equal(entries.size, h.size)
    entries.each{|k, v| assert_equal(v, h[k])}
    assert_equal(nil, h["_not_found_"])
    assert_equal(nil, h[:_not_dound_])
    assert_equal(nil, h[-2])

    k = HashKey[-4]
    h[HashKey[-1]] = -1
    h[k] = -4
    h.delete(k)
    assert_equal(nil, h[k])

    if Object.const_defined?(:Float)
      h[-2] = 22
      assert_equal(nil, h[-2.0])
      h[-3.0] = 33
      assert_equal(nil, h[-3])
      assert_equal(33, h[-3.0])
    end

    k = HashKey[-2]
    k.callback = ->(name, *){h.clear if name == :eql?}
    assert_nothing_crashed{h[k]}
    k.callback = ->(name, *){h.clear if name == :hash}
    assert_nothing_crashed{h[k]}
  end

  # Hash#[] should call #default (#3272)
  h = {}
  def h.default(k); self[k] = 1; end
  h[:foo] += 1
  assert_equal(2, h[:foo])
end

[%w[[]= 3], %w[store 26]].each do |meth, no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [{}, ht_entries.hash_for].each do |h|
      # duplicated key
      k = :_dup_key
      h.__send__(meth, k, 1)
      size = h.size
      h.__send__(meth, k, 2)
      assert_equal(size, h.size)
      assert_equal(2, h[k])

      # freeze string key
      k = "_mutable"
      h.__send__(meth, k, 1)
      h_k = h.keys[-1]
      assert_not_same(k, h_k)
      assert_predicate(h_k, :frozen?)
      assert_not_predicate(k, :frozen?)

      # frozen string key
      k = "_immutable".freeze
      h.__send__(meth, k, 2)
      h_k = h.keys[-1]
      assert_same(k, h_k)
      assert_predicate(h_k, :frozen?)

      # numeric key
      if Object.const_defined?(:Float)
        h.__send__(meth, 3, :fixnum)
        h.__send__(meth, 3.0, :float)
        assert_equal(:fixnum, h[3])
        assert_equal(:float, h[3.0])
        h.__send__(meth, 4.0, :float)
        h.__send__(meth, 4, :fixnum)
        assert_equal(:fixnum, h[4])
        assert_equal(:float, h[4.0])
      end

      # other key
      k = [:_array]
      h.__send__(meth, k, :_array)
      h_k = h.keys[-1]
      assert_same(k, h_k)
      assert_not_predicate(h_k, :frozen?)
      assert_not_predicate(k, :frozen?)

      # deleted key
      k1, k2, k3 = HashKey[-1], HashKey[-4], HashKey[-7]  # same hash code
      h.__send__(meth, k1, 1)
      h.__send__(meth, k2, -4)
      h.__send__(meth, k3, 73)
      size = h.size
      h.delete(k1)
      h.delete(k2)
      h.__send__(meth, k2, 40)
      assert_equal(nil, h[k1])
      assert_equal(40, h[k2])
      assert_equal(73, h[k3])
      assert_equal(size - 1, h.size)

      # frozen
      h.freeze
      assert_raise(FrozenError){h.__send__(meth, -100, 1)}
    end

    [ar_entries.hash_for, ht_entries.hash_for].each do |h|
      k = HashKey[-2]
      k.callback = ->(name, *){h.clear if name == :eql?}
      assert_nothing_crashed{h.__send__(meth, k, 2)}
      k.callback = ->(name, *){h.clear if name == :hash}
      assert_nothing_crashed{h.__send__(meth, k, 2)}
    end
  end
end

assert('Hash#clear', '15.2.13.4.4') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for
    assert_same(h, h.clear)
    assert_equal(0, h.size)
    assert_nil(h[entries.key(3)])

    h.freeze
    assert_raise(FrozenError){h.clear}
  end

  h = {}.freeze
  assert_raise(FrozenError){h.clear}
end

assert('Hash#dup') do
  cls = Class.new(Hash){attr_accessor :foo}
  [ar_entries, ht_entries].each do |entries|
    h1 = entries.hash_for(cls.new(61)){|h| h.foo = 23}.freeze
    h2 = h1.dup
    assert_not_predicate(h2, :frozen?)
    assert_equal(h1.class, h2.class)
    assert_equal(entries, h2.to_a)
    assert_equal(23, h2.foo)
    assert_equal(61, h2["_not_found_"])
    h2[-10] = 10
    assert_equal(10, h2[-10])
    assert_not_operator(h1, :key?, -10)

    h = entries.hash_for
    k = HashKey[-1]
    h[k] = 1
    k.callback = ->(*){h.clear}
    assert_nothing_crashed{h.dup}
  end
end

assert('Hash#default', '15.2.13.4.5') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for(Hash.new)
    assert_equal(nil, h.default)
    assert_equal(nil, h.default(-2))

    h = entries.hash_for(Hash.new(-88))
    assert_equal(-88, h.default)
    assert_equal(-88, h.default(-2))
    assert_not_operator(h, :key?, -2)
    assert_raise(ArgumentError){h.default(-2,-2)}

    proc = ->(h, k){h[k] = k * 3}
    h = entries.hash_for(Hash.new(proc))
    assert_equal(proc, h.default(-2))

    h = entries.hash_for(Hash.new(&proc))
    assert_equal(nil, h.default)
    assert_not_operator(h, :key?, -2)
    assert_equal(-6, h.default(-2))
    assert_equal(-6, h[-2])
    h[-2] = -5
    assert_equal(-6, h.default(-2))
    assert_equal(-6, h[-2])
  end
end

assert('Hash#default=', '15.2.13.4.6') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for(Hash.new)
    h.default = 3
    assert_equal(3, h[-2])
    assert_equal(entries.value(0), h[entries.key(0)])

    h.default = 4
    assert_equal(4, h[-2])

    h.default = nil
    assert_equal(nil, h[-2])

    h.default = [5]
    assert_same(h[-2], h[-3])

    h.freeze
    assert_raise(FrozenError){h.default = 3}
  end
end

assert('Hash#default_proc', '15.2.13.4.7') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for({})
    assert_nil(h.default_proc)

    h = entries.hash_for(Hash.new(34))
    assert_nil(h.default_proc)

    h = entries.hash_for(Hash.new{|h, k| h[k] = k * 3})
    proc = h.default_proc
    assert_equal(Proc, proc.class)
    assert_equal(6, proc.(h, 2))
    assert_equal([2, 6], h.to_a[-1])
  end
end

assert('Hash#delete', '15.2.13.4.8') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for
    pairs = entries.dup
    [0, 2, -1].each do |i|
      k, v = pairs.delete_at(i)
      assert_equal(v, h.delete(k))
      assert_equal(nil, h[k])
      assert_equal(false, h.key?(k))
    end
    [entries.key(0), "_not_found_"].each {|k|assert_equal(nil, h.delete(k))}
    assert_equal(pairs.size, h.size)
    assert_equal(pairs, h.to_a)
    pairs.each {|k, v| assert_equal(v, h[k])}

    h = entries.hash_for
    pairs = entries.dup
    [pairs.delete_at(1), ["_not_found_", "_default"]].each do |k, v|
      assert_equal(v, h.delete(k){"_default"})
      assert_equal(nil, h[k])
      assert_equal(false, h.key?(k))
    end
    assert_equal(pairs.size, h.size)
    assert_equal(pairs, h.to_a)
    pairs.each {|k, v| assert_equal(v, h[k])}

    if Object.const_defined?(:Float)
      h = entries.dup.push([-5, 1], [-5.0, 2], [-6.0, 3], [-6, 4]).hash_for
      assert_equal(1, h.delete(-5))
      assert_equal(3, h.delete(-6.0))
    end

    # nil value with block
    h = entries.hash_for
    k = "_nil"
    h[k] = nil
    assert_equal(nil, h.delete(k){"blk"})
    assert_equal(false, h.key?(k))

    k = HashKey[-31, callback: ->(*){h.clear}]
    assert_nothing_crashed{h.delete(k)}
  end

  assert_raise(ArgumentError){{}.delete}
  assert_raise(ArgumentError){{}.delete(1,2)}

  h = {}.freeze
  assert_raise(FrozenError){h.delete(1)}
end

[%w[each 9], %w[each_key 10], %w[each_value 11]].each do |meth, no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [ar_entries, ht_entries].each do |entries|
      exp = []
      entries.__send__(meth){|param| exp << param}
      assert_iterator(exp, entries.hash_for, meth)

      h = entries.hash_for
      entries.shift
      h.shift
      entry = entries.delete_at(1)
      h.delete(entry[0])
      h.delete(entries.delete_at(-4)[0])
      entries << entry
      h.store(*entry)
      exp = []
      entries.__send__(meth){|param| exp << param}
      assert_iterator(exp, h, meth)
    end

    assert_iterator([], {}, meth)
  end
end

assert('Hash#empty?', '15.2.13.4.12') do
  [ar_entries, ht_entries].each do |entries|
    assert_not_predicate entries.hash_for, :empty?

    h = entries.hash_for
    h.shift
    h.delete(entries.key(-1))
    assert_not_predicate h, :empty?

    h = entries.hash_for
    entries.size.times{h.shift}
    assert_predicate(h, :empty?)

    h = entries.hash_for
    entries.each {|k, v| h.delete(k)}
    assert_predicate(h, :empty?)
  end

  assert_predicate(Hash.new, :empty?)
  assert_predicate(Hash.new(1), :empty?)
  assert_predicate(Hash.new{|h, k| h[k] = 2}, :empty?)
end

[%w[has_key? 13], %w[include? 15], %w[key? 18], %w[member? 21]].each do |meth,no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [ar_entries, ht_entries].each do |entries|
      pairs = entries.dup.push([HashKey[-3], 3], [nil, "NIL"])
      h = pairs.hash_for
      pairs.each{|k, v| assert_operator(h, meth, k)}
      assert_not_operator(h, meth, HashKey[-6])
      assert_not_operator(h, meth, 3)

      if Object.const_defined?(:Float)
        hh = entries.push([-7, :i], [-8.0, :f]).hash_for
        assert_not_operator(hh, meth, -7.0)
        assert_not_operator(hh, meth, -8)
        assert_operator(hh, meth, -8.0)
      end

      h.shift
      assert_not_operator(h, meth, pairs.key(0))

      h.delete(pairs.key(3))
      assert_not_operator(h, meth, pairs.key(3))

      k = HashKey[-31, callback: ->(*){h.clear}]
      assert_nothing_crashed{h.__send__(meth, k)}
    end
  end

  h = Hash.new{|h, k| h[1] = 1}
  assert_not_operator(h, meth, 1)
end

[%w[has_value? 14], %w[value? 24]].each do |meth, no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [ar_entries, ht_entries].each do |entries|
      entries.push([HashKey[-5], -8], ["NIL", nil])
      h = entries.hash_for
      entries.each{|k, v| assert_operator(h, meth, v)}
      assert_operator(h, meth, -8.0) if Object.const_defined?(:Float)
      assert_not_operator(h, meth, "-8")

      h.shift
      assert_not_operator(h, meth, entries.value(0))

      h.delete(entries.key(3))
      assert_not_operator(h, meth, entries.value(3))

      v = HashKey[-31, callback: ->(*){h.clear}]
      assert_nothing_crashed{h.__send__(meth, v)}
    end
  end

  h = Hash.new{|h, k| h[1] = 1}
  assert_not_operator(h, meth, 1)
end

assert('Hash#initialize', '15.2.13.4.16') do
  h = Hash.new
  assert_equal(Hash, h.class)
  assert_not_operator(h, :key?, 1)
  assert_equal(nil, h[1])

  h = Hash.new([8])
  assert_not_operator(h, :key?, 1)
  assert_equal([8], h[1])
  assert_same(h[1], h[2])

  k = "key"
  h = Hash.new{|hash, key| [hash, key]}
  assert_not_operator(h, :key?, k)
  assert_equal([h, k], h[k])
  assert_same(h, h[k][0])
  assert_same(k, h[k][1])

  assert_raise(ArgumentError){Hash.new(1,2)}
  assert_raise(ArgumentError){Hash.new(1){}}
end

[%w[keys 19], %w[values 28]].each do |meth, no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [ar_entries, ht_entries].each do |entries|
      h = entries.hash_for
      assert_equal(entries.__send__(meth), h.__send__(meth))

      h.shift
      entries.shift
      h.delete(entries.delete_at(3)[0])
      assert_equal(entries.__send__(meth), h.__send__(meth))
    end

    assert_equal([], {}.__send__(meth))
  end
end

[%w[length 20], %w[size 25]].each do |meth, no|
  assert("Hash##{meth}", "15.2.13.4.#{no}") do
    [ar_entries, ht_entries].each do |entries|
      h = entries.hash_for
      assert_equal(entries.size, h.__send__(meth))

      h.shift
      entries.shift
      h.delete(entries.delete_at(3)[0])
      assert_equal(entries.size, h.__send__(meth))
    end

    assert_equal(0, Hash.new.__send__(meth))
  end
end

assert('Hash#merge', '15.2.13.4.22') do
  cls = Class.new(Hash){attr_accessor :foo}
  ar_pairs = HashEntries[
    ["id", 32],
    [nil, :two],
    ["&", "&amp;"],
    [:same_key, :AR],
    [HashKey[2], 20],
  ]
  ht_pairs = HashEntries[
    *(1..20).map{[_1, _1.to_s]},
    [:same_key, :HT],
    [:age, 32],
    [HashKey[5], 500],
  ]

  [[ar_pairs, ht_pairs], [ht_pairs, ar_pairs]].each do |entries1, entries2|
    h1 = entries1.hash_for(cls.new(:dv1)){|h| h.foo = :iv1}.freeze
    h2 = entries2.hash_for(Hash.new(:dv2)).freeze
    h3 = h1.merge(h2)
    assert_equal(entries1, h1.to_a)
    assert_equal(merge_entries!(entries1.dup2, entries2), h3.to_a)
    assert_equal(cls, h3.class)
    assert_equal(:dv1, h3.default)
    assert_equal(:iv1, h3.foo)

    h3 = {}.merge(entries2.hash_for(cls.new))
    assert_equal(merge_entries!([], entries2), h3.to_a)
    assert_equal(Hash, h3.class)

    h3 = entries1.hash_for.merge({})
    assert_equal(merge_entries!(entries1.dup2, []), h3.to_a)

    h1 = entries1.hash_for
    h2 = entries2.hash_for
    h3 = h1.merge(h2){|k, v1, v2| [k, v1, v2]}
    exp = merge_entries!(entries1.dup2, entries2)
    exp.find{|k, _| k == :same_key}[1] = [
      :same_key,
      entries1.find{|k, _| k == :same_key}[1],
      entries2.find{|k, _| k == :same_key}[1],
    ]
    assert_equal(exp, h3.to_a)

    assert_raise(TypeError){entries1.hash_for.merge("str")}

    k2 = HashKey[-2]
    entries2 << [k2, 234]
    h1, h2 = entries1.hash_for, entries2.hash_for
    k2.callback = ->(name, *){h1.clear if name == :eql?}
    assert_nothing_crashed{h1.merge(h2)}
    h1, h2 = entries1.hash_for, entries2.hash_for
    k2.callback = ->(name, *){h2.clear if name == :eql?}
    assert_nothing_crashed{h1.merge(h2)}
    h1, h2 = entries1.hash_for, entries2.hash_for
    k2.callback = ->(name, *){h1.clear if name == :hash}
    assert_nothing_crashed{h1.merge(h2)}
    h1, h2 = entries1.hash_for, entries2.hash_for
    k2.callback = ->(name, *){h2.clear if name == :hash}
    assert_nothing_crashed{h1.merge(h2)}
  end
end

assert("Hash#replace", "15.2.13.4.23") do
  cls = Class.new(Hash){attr_accessor :foo}
  e = [ar_entries, ht_entries]
  [e, e.reverse].each do |entries1, entries2|
    h1 = entries1.hash_for
    assert_same(h1, h1.replace(h1))
    assert_equal(entries1, h1.to_a)

    h1 = {}
    assert_same(h1, h1.replace(entries2.hash_for))
    assert_equal(entries2, h1.to_a)

    h1 = entries1.hash_for
    assert_same(h1, h1.replace({}))
    assert_predicate(h1, :empty?)

    pairs2 = entries2.dup
    h2 = pairs2.hash_for
    pairs2.shift
    h2.shift
    h2.delete(pairs2.delete_at(2)[0])
    h2.delete(pairs2.delete_at(4)[0])
    h1 = entries1.hash_for
    assert_same(h1, h1.replace(h2))
    assert_equal(pairs2, h1.to_a)

    h1 = entries1.hash_for(Hash.new(10))
    h2 = entries2.hash_for(Hash.new(20))
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)
    assert_equal(20, h1.default)

    h1 = entries1.hash_for(Hash.new{_2})
    h2 = entries2.hash_for(Hash.new{_2.to_s})
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)
    assert_equal("-11", h1[-11])

    h1 = entries1.hash_for(Hash.new(10))
    h2 = entries2.hash_for(Hash.new{_2.to_s})
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)
    assert_equal("-11", h1[-11])

    h1 = entries1.hash_for(Hash.new{_2})
    h2 = entries2.hash_for(Hash.new(20))
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)
    assert_equal(20, h1[-1])

    h1 = entries1.hash_for(cls.new(10)){|h| h.foo = 41}
    h2 = entries2.hash_for(cls.new(20)){|h| h.foo = 42}.freeze
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)
    assert_equal(20, h1.default)
    assert_equal(41, h1.foo)

    h1 = entries1.hash_for
    h2 = entries2.hash_for(cls.new)
    assert_same(h1, h1.replace(h2))
    assert_equal(entries2, h1.to_a)

    assert_raise(TypeError){entries1.hash_for.replace([])}

    k2 = HashKey[-2]
    pairs2 = entries2.dup
    pairs2 << [k2, 23]
    h1 = entries1.hash_for
    h2 = pairs2.hash_for
    k2.callback = ->(*){h1.clear; h2.clear}
    assert_nothing_crashed{h1.replace(h2)}

    assert_raise(FrozenError){h1.freeze.replace(h1)}
    assert_raise(FrozenError){{}.freeze.replace({})}
  end
end

assert('Hash#shift', '15.2.13.4.24') do
  [ar_entries, ht_entries].each do |entries|
    pairs = entries.dup
    h = pairs.hash_for
    h.delete(pairs.delete_at(0)[0])
    h.delete(pairs.delete_at(3)[0])
    until pairs.empty?
      exp = pairs.shift
      act = h.shift
      assert_equal(Array, act.class)
      assert_equal(exp, act)
      assert_equal(exp.size, act.size)
      assert_not_operator(h, :key?, exp[0])
    end

    assert_equal(nil, h.shift)
    assert_equal(0, h.size)

    h.default = -456
    assert_equal(nil, h.shift)
    assert_equal(0, h.size)

    h.freeze
    assert_raise(FrozenError){h.shift}
  end

  h = Hash.new{|h, k| [h, k]}
  assert_equal(0, h.size)
  assert_equal(nil, h.shift)
end

# Not ISO specified

%i[reject select].each do |meth|
  assert("Hash##{meth}") do
    cls = Class.new(Hash){attr_accessor :foo}
    [ar_entries, ht_entries].each do |entries|
      params = nil
      filter = ->((k, v)) do
        params << [k, v]
        String === k
      end

      h = entries.hash_for(cls.new(1))
      params = []
      ret = h.__send__(meth, &filter)
      assert_equal(entries, params)
      assert_equal(entries, h.to_a)
      assert_equal(1, h.default)
      assert_equal(entries.__send__(meth, &filter), ret.to_a)
      assert_equal(Hash, ret.class)
      assert_equal(nil, ret.default)

      params = []
      assert_predicate({}.__send__(meth, &filter), :empty?)
      assert_predicate(params, :empty?)
    end
  end
end

%i[reject! select!].each do |meth|
  assert("Hash##{meth}") do
    [ar_entries, ht_entries].each do |entries|
      params = nil
      filter = ->((k, v)) do
        params << [k, v]
        String === k
      end

      pairs = entries.dup << ["_str", 5]
      h = pairs.hash_for(Hash.new(1))
      params = []
      ret = h.__send__(meth, &filter)
      assert_same(h, ret)
      assert_equal(pairs, params)
      assert_equal(pairs.__send__(meth.to_s[0..-2], &filter), h.to_a)
      assert_equal(1, h.default)

      h = pairs.hash_for
      ret = h.__send__(meth){meth == :select!}
      assert_nil(ret)
      assert_equal(pairs, h.to_a)

      assert_raise(FrozenError){h.freeze.__send__(meth, &filter)}
    end

    h = {}
    assert_nil(h.__send__(meth){})
    assert_predicate(h, :empty?)
  end
end

%i[inspect to_s].each do |meth|
  assert("Hash##{meth}") do
    assert_equal('{}', Hash.new.__send__(meth))

    h1 = {:s => 0, :a => [1,2], 37 => :b, :d => "del", "c" => nil}
    h1.shift
    h1.delete(:d)
    s1 = ':a=>[1, 2], 37=>:b, "c"=>nil'
    h2 = Hash.new(100)

    (1..14).each{h2[_1] = _1 * 2}
    h2 = {**h2, **h1}
    s2 = "1=>2, 2=>4, 3=>6, 4=>8, 5=>10, 6=>12, 7=>14, 8=>16, " \
         "9=>18, 10=>20, 11=>22, 12=>24, 13=>26, 14=>28, #{s1}"

    [[h1, s1], [h2, s2]].each do |h, s|
      assert_equal("{#{s}}", h.__send__(meth))

      hh = {}
      hh[:recur] = hh
      h.each{|k, v| hh[k] = v}
      assert_equal("{:recur=>{...}, #{s}}", hh.__send__(meth))

      hh = h.dup
      hh[hh] = :recur
      assert_equal("{#{s}, {...}=>:recur}", hh.__send__(meth))
    end

    [ar_entries, ht_entries].each do |entries|
      cls = Class.new do
        attr_accessor :h
        def inspect; @h.replace(@h.dup); to_s; end
      end
      v = cls.new
      h = entries.hash_for({_k: v})
      v.h = h
      assert_nothing_raised{h.__send__(meth)}
    end
  end
end

assert('Hash#rehash') do
  cls = Class.new(Hash){attr_accessor :foo}
  [ar_entries, ht_entries].each do |entries|
    k1, k2, k3 = HashKey[-1], HashKey[-2], HashKey[-3]
    pairs = entries.dup.push(
      [-4, -40],
      [HashKey[-11], -5],
      [:_del, "_del"],
      [k1, :_k1],
      ["_a", "_b"],
      [k2, :_k2],
      ["_c", "_d"],
      [HashKey[-22], -21],
      [k3, :_k3],
    )
    h = pairs.hash_for(cls.new(:defvar)){|h| h.foo = "f"}
    k1.value, k2.value, k3.value = -11, -11, -22
    pairs1 = pairs.dup
    pairs1.delete([:_del, h.delete(:_del)])
    exp_pairs1 = pairs1.hash_for.to_a
    h.freeze
    assert_same(h, h.rehash)
    assert_equal(exp_pairs1, h.to_a)
    assert_equal(exp_pairs1.size, h.size)
    assert_equal(:defvar, h.default)
    assert_equal("f", h.foo)
    exp_pairs1.each {|k, v| assert_equal(v, h[k])}

    # If an error occurs during rehash, at least the entry list is not broken.
    k1.value, k2.value, k3.value = -1, -2, -3
    h = pairs.hash_for
    k1.value = -11
    pairs2 = pairs.dup
    pairs2.delete([:_del, h.delete(:_del)])
    exp_pairs2 = pairs2.hash_for.to_a
    k2.error = :eql?
    assert_raise{h.rehash}
    act_pairs2 = h.to_a
    unless pairs2 == act_pairs2 && pairs2.size == h.size
      assert_equal(exp_pairs2, act_pairs2)
      assert_equal(exp_pairs2.size, h.size)
    end

    k1.value = -1
    k2.error = false
    h = pairs.hash_for
    k1.callback = ->(name, *){h.clear if name == :eql?}
    assert_nothing_crashed{h.rehash}
    k1.callback = ->(name, *){h.clear if name == :hash}
    assert_nothing_crashed{h.rehash}
  end

  h = {}
  assert_same(h, h.rehash)
  assert_predicate(h, :empty?)

  h = {}
  (1..17).each{h[_1] = _1 * 2}
  (2..16).each{h.delete(_1)}
  assert_same(h, h.rehash)
  assert_equal([[1, 2], [17, 34]], h.to_a)
  assert_equal(2, h.size)
  [1, 17].each{assert_equal(_1 * 2, h[_1])}
end

assert('#eql? receiver should be specified key') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for
    k0 = HashKey[-99]
    h[k0] = 1

    k1 = HashKey[-3, error: :eql?]
    assert_raise{h[k1]}
    k0.error = :eql?
    k1.error = false
    assert_nothing_raised{h[k1]}

    k0.error = false
    k1.error = :eql?
    assert_raise{h[k1] = 1}
    k0.error = :eql?
    k1.error = false
    assert_nothing_raised{h[k1] = 1}

    k0.error = false
    k2 = HashKey[-6, error: :eql?]
    assert_raise{h.delete(k2)}
    k0.error = :eql?
    k2.error = false
    assert_nothing_raised{h.delete(k2)}

    k0.error = false
    k3 = HashKey[-9, error: :eql?]
    %i[has_key? include? key? member?].each do |m|
      assert_raise{h.__send__(m, k3)}
    end
    k0.error = :eql?
    k3.error = false
    %i[has_key? include? key? member?].each do |m|
      assert_nothing_raised{h.__send__(m, k3)}
    end
  end
end

assert('#== receiver should be specified value') do
  [ar_entries, ht_entries].each do |entries|
    h = entries.hash_for
    v0 = HashKey[-99]
    h[-99] = v0

    v1 = HashKey[-3, error: :==]
    %i[has_value? value?].each{|m| assert_raise{h.__send__(m, v1)}}
    v0.error = :==
    v1.error = false
    %i[has_value? value?].each{|m| assert_nothing_raised{h.__send__(m, v1)}}
  end
end

assert('test value ommision') do
  x = 1
  y = 2
  assert_equal({x:1, y:2}, {x:, y:})
end
