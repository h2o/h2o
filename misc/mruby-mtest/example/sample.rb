class Test4MTest < MTest::Unit::TestCase
  def test_assert
    assert(true)
    assert(true, 'true sample test')
  end

  def test_assert_block
    assert_block('msg') do
      'something-block'
    end
  end

  def test_assert_empty
    assert_empty('', 'string empty')
    assert_empty([], 'array empty')
    assert_empty({}, 'hash empty')
  end

  def test_assert_equal
    assert_equal('', nil.to_s)
  end

  def test_assert_in_delta
    assert_in_delta(0, 0.1, 0.5)
  end

  def test_assert_includes
    assert_include([1,2,3], 1)
  end

  def test_assert_instance_of
    assert_instance_of Array, []
    assert_instance_of Class, Array
  end

  def test_assert_kind_of
    assert_kind_of Array, []
    assert_kind_of Class, Array
  end

  def test_assert_match
    assert_match 'abc', 'abc'
  end
end

MTest::Unit.new.run
