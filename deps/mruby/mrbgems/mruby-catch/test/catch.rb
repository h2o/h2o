assert "return throw value" do
  val = ["val"]
  result = catch :foo do
    loop do
      loop do
        begin
          throw :foo, val
        rescue Exception
          flunk("should not reach here 1")
        end
        break
      end
      flunk("should not reach here 2")
    end
    false
  end
  assert_same(val, result)
end

assert "no throw" do
  assert_equal(:foo, catch(:bar){:foo})
end

assert "no throw value" do
  result = catch :foo do
    throw :foo
    1
  end
  assert_equal(nil, result)
end

assert "pass the given tag to block" do
  tag = [:foo]
  catch(tag){|t| assert_same(tag, t)}
end

assert "tag identity, uncaught throw" do
  tag, val = [:tag], [:val]
  catch [:tag] do
    throw tag, val
  end
  flunk("should not reach here")
rescue Exception => e
  assert_match("uncaught throw *", e.message)
  assert_same(tag, e.tag)
  assert_same(val, e.value)
end

assert "without catch arguments" do
  result = catch do |tag1|
    catch do |tag2|
      throw tag1, 1
      flunk("should not reach here 1")
    end
    flunk("should not reach here 2")
  end
  assert_equal(1, result)
end

assert "catches across invocation boundaries" do
  v = []
  catch :one do
    v << 1
    catch :two do
      v << 2
      throw :one
      v << 3
    end
    v << 4
  end
  assert_equal([1,2], v)
end

assert "catches in the nested invocation with the same key" do
  v = []
  catch :tag do
    v << 1
    catch :tag do
      v << 2
      throw :tag
      v << 3
    end
    v << 4
  end
  assert_equal([1,2,4], v)
end
