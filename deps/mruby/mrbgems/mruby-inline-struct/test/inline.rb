##
# InlineStruct Test

class InlineStructTest
  def extra_method
    :ok
  end

  def test_ivar_set
    @var = :ivar
  end

  def test_ivar_get
    @vat
  end
end

assert('InlineStructTest#dup') do
  obj = InlineStructTest.new(1)
  assert_equal obj.to_s, 'fixnum'
  assert_equal obj.dup.to_s, 'fixnum'
end

assert('InlineStructTest#clone') do
  obj = InlineStructTest.new(1)
  assert_equal obj.to_s, 'fixnum'
  assert_equal obj.clone.to_s, 'fixnum'
end

assert('InlineStruct#object_id') do
  obj1 = InlineStructTest.new(1)
  obj2 = InlineStructTest.new(1)
  assert_not_equal obj1, obj2
  assert_not_equal obj1.object_id, obj2.object_id
  assert_not_equal obj1.object_id, obj1.dup.object_id
  assert_not_equal obj1.object_id, obj1.clone.object_id
end

assert('InlineStructTest#mutate (dup)') do
  obj1 = InlineStructTest.new("foo")
  assert_equal obj1.to_s, "string"
  obj2 = obj1.dup
  assert_equal obj2.to_s, "string"
  obj1.mutate
  assert_equal obj1.to_s, "mutate"
  assert_equal obj2.to_s, "string"
end

assert('InlineStructTest#mutate (clone)') do
  obj1 = InlineStructTest.new("foo")
  assert_equal obj1.to_s, "string"
  obj2 = obj1.clone
  assert_equal obj2.to_s, "string"
  obj1.mutate
  assert_equal obj1.to_s, "mutate"
  assert_equal obj2.to_s, "string"
end

assert('InlineStructTest#test_receive(string)') do
  assert_equal InlineStructTest.test_receive(InlineStructTest.new('a')), true
end

assert('InlineStructTest#test_receive(float)') do
  assert_equal InlineStructTest.test_receive(InlineStructTest.new(1.25)), false
end

assert('InlineStructTest#test_receive(invalid object)') do
  assert_raise(TypeError) do
    InlineStructTest.test_receive([])
  end
end

assert('InlineStructTest#test_receive(string)') do
  assert_equal InlineStructTest.test_receive_direct(InlineStructTest.new('a')), true
end

assert('InlineStructTest#test_receive(float)') do
  assert_equal InlineStructTest.test_receive_direct(InlineStructTest.new(1.25)), false
end

assert('InlineStructTest#test_receive(invalid object)') do
  assert_raise(TypeError) do
    InlineStructTest.test_receive_direct([])
  end
end

assert('InlineStructTest#extra_method') do
  assert_equal InlineStructTest.new(1).extra_method, :ok
end

assert('InlineStructTest instance variable') do
  obj = InlineStructTest.new(1)
  assert_raise(ArgumentError) do
    obj.test_ivar_set
  end
  assert_equal obj.test_ivar_get, nil
end

# 64-bit mode
if InlineStructTest.length == 24
  assert('InlineStructTest length [64 bit]') do
    assert_equal InlineStructTest.length, 3 * 8
  end
end

# 32-bit mode
if InlineStructTest.length == 12
  assert('InlineStructTest length [32 bit]') do
    assert_equal InlineStructTest.length, 3 * 4
  end
end

# 16-bit mode
if InlineStructTest.length == 6
  assert('InlineStructTest length [16 bit]') do
    assert_equal InlineStructTest.length, 3 * 2
  end
end
