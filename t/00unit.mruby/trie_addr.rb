$LOAD_PATH << 'share/h2o/mruby'
require 'misc/mruby-mtest/mrblib/mtest_unit.rb'
require 'trie_addr.rb'

class TrieAddrTest < MTest::Unit::TestCase
  def test_basic
    addr = TrieAddr.new
    addr.add("10.0.0.0/12")
    addr.add("10.255.0.0/12")

    assert_true(addr.match?("10.10.0.0"))
    assert_false(addr.match?("10.128.0.0"))
    assert_true(addr.match?("10.250.0.0"))

    addr.add("10.255.0.0/8")
    assert_true(addr.match?("10.128.0.0"))

  end

  def test_missing_prefix_length
    addr = TrieAddr.new
    addr.add("12.34.56.78")

    assert_false(addr.match?("12.34.56.77"))
    assert_true(addr.match?("12.34.56.78"))
    assert_false(addr.match?("12.34.56.79"))
  end

  def test_ipv6_addr
    addr = TrieAddr.new
    assert_raise(ArgumentError, "ipv6 is currently not supported") { addr.add("::1") }
    assert_false(addr.match?("::1"), "always returns false")
  end

  def test_invalid_addr
    addr = TrieAddr.new
    addr.add("0.0.0.0/8")
    assert_false(addr.match?("hogehoge"))
  end

  # taken from https://github.com/hirose31/p5-net-ip-match?-trie/blob/master/t/10_match?_ip_PP.t
  def test_nimt_cases
    addr = TrieAddr.new
    addr.add(["10.0.0.0/24", "10.0.1.0/24", "11.0.0.0/16", "10.1.0.0/28", "10.0.0.0/8", "10.2.0.0/24"])

    cases = [
      { :name => "match 1",         :input => "10.0.0.100",      :expected => true },
      { :name => "match 2",         :input => "10.1.0.8",        :expected => true },
      { :name => "match 3",         :input => "10.2.0.1",        :expected => true },
      { :name => "not match",       :input => "192.168.1.2",     :expected => false },
      { :name => "match min",       :input => "10.0.0.0",        :expected => true },
      { :name => "match max",       :input => "10.0.0.255",      :expected => true },
      { :name => "invalid IP",      :input => "11.0.999.1",      :expected => false },
      { :name => "0.0.0.0",         :input => "0.0.0.0",         :expected => false },
      { :name => "255.255.255.255", :input => "255.255.255.255", :expected => false },
      { :name => "big",             :input => "10.255.255.255",  :expected => true },
    ]
    cases.each {|c|
      assert_equal(c[:expected], addr.match?(c[:input]), c[:name])
    }
  end
end

MTest::Unit.new.run
