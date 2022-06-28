##
# Exception ISO Test

assert('Exception', '15.2.22') do
  assert_equal Class, Exception.class
end

assert('Exception.exception', '15.2.22.4.1') do
  e = Exception.exception('a')

  assert_equal Exception, e.class
end

assert('Exception#exception', '15.2.22.5.1') do
  e = Exception.new
  re = RuntimeError.new
  assert_equal e, e.exception
  assert_equal e, e.exception(e)
  assert_equal re, re.exception(re)
  changed_re = re.exception('message has changed')
  assert_not_equal re, changed_re
  assert_equal 'message has changed', changed_re.message
end

assert('Exception#message', '15.2.22.5.2') do
  e = Exception.exception('a')

  assert_equal 'a', e.message
end

assert('Exception#to_s', '15.2.22.5.3') do
  e = Exception.exception('a')

  assert_equal 'a', e.to_s
end

assert('Exception.exception', '15.2.22.4.1') do
  e = Exception.exception()
  e.initialize('a')

  assert_equal 'a', e.message
end

assert('NameError', '15.2.31') do
  assert_raise(NameError) do
    raise NameError.new
  end

  e = NameError.new "msg", "name"
  assert_equal "msg", e.message
  assert_equal "name", e.name
end

assert('ScriptError', '15.2.37') do
  assert_raise(ScriptError) do
    raise ScriptError.new
  end
end

assert('SyntaxError', '15.2.38') do
  assert_raise(SyntaxError) do
    raise SyntaxError.new
  end
end

# Not ISO specified

assert('Exception 1') do
r=begin
    1+1
  ensure
    2+2
  end
  assert_equal 2, r
end

assert('Exception 2') do
r=begin
    1+1
    begin
      2+2
    ensure
      3+3
    end
  ensure
    4+4
  end
  assert_equal 4, r
end

assert('Exception 3') do
r=begin
    1+1
    begin
      2+2
    ensure
      3+3
    end
  ensure
    4+4
    begin
      5+5
    ensure
      6+6
    end
  end
  assert_equal 4, r
end

assert('Exception 4') do
  a = nil
  1.times{|e|
    begin
    rescue => err
    end
    a = err.class
  }
  assert_equal NilClass, a
end

assert('Exception 5') do
  $ans = []
  def m
    $!
  end
  def m2
    1.times{
      begin
        return
      ensure
        $ans << m
      end
    }
  end
  m2
  assert_equal [nil], $ans
end

assert('Exception 6') do
  $i = 0
  def m
    iter{
      begin
        $i += 1
        begin
          $i += 2
          break
        ensure

        end
      ensure
        $i += 4
      end
      $i = 0
    }
  end

  def iter
    yield
  end
  m
  assert_equal 7, $i
end

assert('Exception 7') do
  $i = 0
  def m
    begin
      $i += 1
      begin
        $i += 2
        return
      ensure
        $i += 3
      end
    ensure
      $i += 4
    end
    p :end
  end
  m
  assert_equal 10, $i
end

assert('Exception 8') do
r=begin
    1
  rescue
    2
  else
    3
  end
  assert_equal 3, r
end

assert('Exception 9') do
r=begin
    1+1
  rescue
    2+2
  else
    3+3
  ensure
    4+4
  end
  assert_equal 6, r
end

assert('Exception 10') do
r=begin
    1+1
    begin
      2+2
    rescue
      3+3
    else
      4+4
    end
  rescue
    5+5
  else
    6+6
  ensure
    7+7
  end
  assert_equal 12, r
end

assert('Exception 11') do
  a = :ok
  begin
    begin
      raise Exception
    rescue
      a = :ng
    end
  rescue Exception
  end
  assert_equal :ok, a
end

assert('Exception 12') do
  a = :ok
  begin
    raise Exception rescue a = :ng
  rescue Exception
  end
  assert_equal :ok, a
end

assert('Exception 13') do
  a = :ng
  begin
    raise StandardError
  rescue TypeError, ArgumentError
    a = :ng
  rescue
    a = :ok
  else
    a = :ng
  end
  assert_equal :ok, a
end

assert('Exception 14') do
  def (o = Object.new).exception_test14; UnknownConstant end
  a = :ng
  begin
    o.__send__(:exception_test14)
  rescue
    a = :ok
  end

  assert_equal :ok, a
end

assert('Exception 15') do
  a = begin
        :ok
      rescue
        :ko
      end
  assert_equal :ok, a
end

assert('Exception 16') do
  begin
    raise "foo"
    false
  rescue => e
    assert_equal "foo", e.message
  end
end

assert('Exception 17') do
r=begin
    raise "a"  # RuntimeError
  rescue ArgumentError
    1
  rescue StandardError
    2
  else
    3
  ensure
    4
  end
  assert_equal 2, r
end

assert('Exception 18') do
r=begin
    0
  rescue ArgumentError
    1
  rescue StandardError
    2
  else
    3
  ensure
    4
  end
  assert_equal 3, r
end

assert('Exception 19') do
  class Class4Exception19
    def a
      r = @e = false
      begin
        b
      rescue TypeError
        r = self.z
      end
      [ r, @e ]
    end

    def b
      begin
        1 * "b"
      ensure
        @e = self.zz
      end
    end

    def zz
      true
    end
    def z
      true
    end
  end
  assert_equal [true, true], Class4Exception19.new.a
end

assert('Exception#inspect') do
  assert_equal "Exception", Exception.new.inspect
  assert_equal "Exception", Exception.new("").inspect
  assert_equal "error! (Exception)", Exception.new("error!").inspect
end

assert('Exception#backtrace') do
  assert_nothing_raised do
    begin
      raise "get backtrace"
    rescue => e
      e.backtrace
    end
  end
end

assert('Raise in ensure') do
  assert_raise(ArgumentError) do
    begin
      raise "" # RuntimeError
    ensure
      raise ArgumentError
    end
  end
end

def backtrace_available?
  begin
    raise "XXX"
  rescue => exception
    not exception.backtrace.empty?
  end
end

assert('GC in rescue') do
  skip "backtrace isn't available" unless backtrace_available?

  line = nil
  begin
    [1].each do
      [2].each do
        [3].each do
          line = __LINE__; raise "XXX"
        end
      end
    end
  rescue => exception
    GC.start
    assert_equal("#{__FILE__}:#{line}",
                 exception.backtrace.first)
  end
end

assert('Method call in rescue') do
  skip "backtrace isn't available" unless backtrace_available?

  line = nil
  begin
    [1].each do
      [2].each do
        line = __LINE__; raise "XXX"
      end
    end
  rescue => exception
    [3].each do
    end
    assert_equal("#{__FILE__}:#{line}",
                 exception.backtrace.first)
  end
end
