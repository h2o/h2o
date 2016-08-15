##
# Test of Minimal Test framework for mruby.
#

if Object.const_defined?(:MTest)
  class Test4MTest < MTest::Unit::TestCase
    def test_assert
      assert(true)
      assert(true, 'true sample test')
      assert_true(true)
      assert_false(false)
      assert_nil(nil)
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
      assert_not_equal('a', nil.to_s)
    end

    def test_assert_in_delta
      assert_in_delta(0, 0.1, 0.5)
    end

    def test_assert_include
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

    def test_assert_raise
      assert_raise(RuntimeError) do
        raise
      end
    end

    def test_assert_false_failure
      assert_raise(MTest::Assertion) do
        assert_false(true)
      end
    end
  end

  if $ok_test
    MTest::Unit.new.mrbtest
  else
    MTest::Unit.new.run
  end
else
  $asserts << "test skip of mruby-mtest/test/mtest_unit_test.rb"  if $asserts
end
