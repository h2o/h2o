##
# ENV test
#

if Object.const_defined?(:MTest)
  class ENVTest < MTest::Unit::TestCase
    def test_env_class
      assert_equal(Object, ENV.class)
    end

    def setup
      @env_hash = ENV.to_hash
      ENV.clear
    end

    def teardown
      ENV.clear
      @env_hash.each do |k, v|
        ENV[k] = v
      end
    end

    def set_dummy_env
      ENV['FOO'] = 'bar'
    end

    def test_size_empty
      assert_equal(0, ENV.size)
    end

    def test_keys_empty
      assert_empty(ENV.keys)
    end

    def test_values_empty
      assert_empty(ENV.values)
    end

    def test_env_to_s_empty
      assert_equal("ENV", ENV.to_s)
    end

    def test_env_inspect_empty
      assert_equal("{}", ENV.inspect)
    end

    def test_env_to_hash_empty
      assert_equal({}, ENV.to_hash)
    end

    def test_env_get_val
      set_dummy_env
      assert_equal('bar', ENV['FOO'])
    end

    def test_env_keys
      set_dummy_env
      assert_equal(['FOO'], ENV.keys)
    end

    def test_env_values
      set_dummy_env
      assert_equal(['bar'], ENV.values)
    end

    def test_env_to_s
      set_dummy_env
      assert_equal("ENV", ENV.to_s)
    end

    def test_env_has_key
      set_dummy_env
      assert_true  ENV.has_key?("FOO")
      assert_false ENV.has_key?("BAR")
    end

    def test_env_inspect
      set_dummy_env
      assert_equal("{\"FOO\"=>\"bar\"}", ENV.inspect)
    end

    def test_env_delete
      set_dummy_env
      old = ENV['FOO']
      ret = ENV.delete('FOO')
      assert_equal(0, ENV.size)
      assert_equal(old, ret)
      assert_equal(nil, ENV.delete('nosuchenv'))
    end

    def test_env_subst_nil
      set_dummy_env
      ENV['FOO'] = nil
      assert_equal(0, ENV.size)
    end

    def test_env_store
      ENV['a'] = 'b'
      assert_equal 'b', ENV['a']

      ENV['a'] = 'c'
      assert_equal 'c', ENV['a']

      ENV['a'] = nil
      assert_equal nil, ENV['a']

      ENV['b'] = nil
      assert_equal nil, ENV['b']
      assert_equal 0, ENV.size
    end
  end

  if $ok_test
    MTest::Unit.new.mrbtest
  else
    MTest::Unit.new.run
  end
else
  $asserts << "test skip of mruby-env/test/env_test.rb"  if $asserts
end

