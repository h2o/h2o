$ok_test = 0
$ko_test = 0
$kill_test = 0
$asserts  = []
$test_start = Time.now if Object.const_defined?(:Time)

# Implementation of print due to the reason that there might be no print
def t_print(*args)
  i = 0
  len = args.size
  while i < len
    str = args[i].to_s
    __t_printstr__ str rescue print str
    i += 1
  end
end

##
# Create the assertion in a readable way
def assertion_string(err, str, iso=nil, e=nil, bt=nil)
  msg = "#{err}#{str}"
  msg += " [#{iso}]" if iso && iso != ''
  msg += " => #{e.message}" if e
  msg += " (mrbgems: #{GEMNAME})" if Object.const_defined?(:GEMNAME)
  if $mrbtest_assert && $mrbtest_assert.size > 0
    $mrbtest_assert.each do |idx, assert_msg, diff|
      msg += "\n - Assertion[#{idx}] Failed: #{assert_msg}\n#{diff}"
    end
  end
  msg += "\nbacktrace:\n\t#{bt.join("\n\t")}" if bt
  msg
end

##
# Verify a code block.
#
# str : A remark which will be printed in case
#       this assertion fails
# iso : The ISO reference code of the feature
#       which will be tested by this
#       assertion
def assert(str = 'Assertion failed', iso = '')
  t_print(str, (iso != '' ? " [#{iso}]" : ''), ' : ') if $mrbtest_verbose
  begin
    $mrbtest_assert = []
    $mrbtest_assert_idx = 0
    yield
    if($mrbtest_assert.size > 0)
      $asserts.push(assertion_string('Fail: ', str, iso, nil))
      $ko_test += 1
      t_print('F')
    else
      $ok_test += 1
      t_print('.')
    end
  rescue Exception => e
    bt = e.backtrace if $mrbtest_verbose
    if e.class.to_s == 'MRubyTestSkip'
      $asserts.push "Skip: #{str} #{iso} #{e.cause}"
      t_print('?')
    else
      $asserts.push(assertion_string("#{e.class}: ", str, iso, e, bt))
      $kill_test += 1
      t_print('X')
    end
  ensure
    $mrbtest_assert = nil
  end
  t_print("\n") if $mrbtest_verbose
end

def assertion_diff(exp, act)
  "    Expected: #{exp.inspect}\n" +
  "      Actual: #{act.inspect}"
end

def assert_true(ret, msg = nil, diff = nil)
  if $mrbtest_assert
    $mrbtest_assert_idx += 1
    unless ret
      msg = "Expected #{ret.inspect} to be true" unless msg
      diff = assertion_diff(true, ret)  unless diff
      $mrbtest_assert.push([$mrbtest_assert_idx, msg, diff])
    end
  end
  ret
end

def assert_false(ret, msg = nil, diff = nil)
  if $mrbtest_assert
    $mrbtest_assert_idx += 1
    if ret
      msg = "Expected #{ret.inspect} to be false" unless msg
      diff = assertion_diff(false, ret) unless diff

      $mrbtest_assert.push([$mrbtest_assert_idx, msg, diff])
    end
  end
  !ret
end

def assert_equal(arg1, arg2 = nil, arg3 = nil)
  if block_given?
    exp, act, msg = arg1, yield, arg2
  else
    exp, act, msg = arg1, arg2, arg3
  end

  msg = "Expected to be equal" unless msg
  diff = assertion_diff(exp, act)
  assert_true(exp == act, msg, diff)
end

def assert_not_equal(arg1, arg2 = nil, arg3 = nil)
  if block_given?
    exp, act, msg = arg1, yield, arg2
  else
    exp, act, msg = arg1, arg2, arg3
  end

  msg = "Expected to be not equal" unless msg
  diff = assertion_diff(exp, act)
  assert_false(exp == act, msg, diff)
end

def assert_nil(obj, msg = nil)
  msg = "Expected #{obj.inspect} to be nil" unless msg
  diff = assertion_diff(nil, obj)
  assert_true(obj.nil?, msg, diff)
end

def assert_include(collection, obj, msg = nil)
  msg = "Expected #{collection.inspect} to include #{obj.inspect}" unless msg
  diff = "    Collection: #{collection.inspect}\n" +
         "        Object: #{obj.inspect}"
  assert_true(collection.include?(obj), msg, diff)
end

def assert_not_include(collection, obj, msg = nil)
  msg = "Expected #{collection.inspect} to not include #{obj.inspect}" unless msg
  diff = "    Collection: #{collection.inspect}\n" +
         "        Object: #{obj.inspect}"
  assert_false(collection.include?(obj), msg, diff)
end

def assert_raise(*exc)
  return true unless $mrbtest_assert
  $mrbtest_assert_idx += 1

  msg = (exc.last.is_a? String) ? exc.pop : nil

  begin
    yield
    msg ||= "Expected to raise #{exc} but nothing was raised."
    diff = nil
    $mrbtest_assert.push [$mrbtest_assert_idx, msg, diff]
    false
  rescue *exc
    true
  rescue Exception => e
    msg ||= "Expected to raise #{exc}, not"
    diff = "      Class: <#{e.class}>\n" +
           "    Message: #{e.message}"
    $mrbtest_assert.push [$mrbtest_assert_idx, msg, diff]
    false
  end
end

def assert_nothing_raised(msg = nil)
  return true unless $mrbtest_assert
  $mrbtest_assert_idx += 1

  begin
    yield
    true
  rescue Exception => e
    msg ||= "Expected not to raise #{exc.join(', ')} but it raised"
    diff =  "      Class: <#{e.class}>\n" +
            "    Message: #{e.message}"
    $mrbtest_assert.push [$mrbtest_assert_idx, msg, diff]
    false
  end
end

##
# Fails unless +obj+ is a kind of +cls+.
def assert_kind_of(cls, obj, msg = nil)
  msg = "Expected #{obj.inspect} to be a kind of #{cls}, not #{obj.class}" unless msg
  diff = assertion_diff(cls, obj.class)
  assert_true(obj.kind_of?(cls), msg, diff)
end

##
# Fails unless +exp+ is equal to +act+ in terms of a Float
def assert_float(exp, act, msg = nil)
  msg = "Float #{exp} expected to be equal to float #{act}" unless msg
  diff = assertion_diff(exp, act)
  assert_true check_float(exp, act), msg, diff
end

##
# Report the test result and print all assertions
# which were reported broken.
def report()
  t_print("\n")

  $asserts.each do |msg|
    t_print "#{msg}\n"
  end

  $total_test = $ok_test+$ko_test+$kill_test
  t_print("Total: #{$total_test}\n")

  t_print("   OK: #{$ok_test}\n")
  t_print("   KO: #{$ko_test}\n")
  t_print("Crash: #{$kill_test}\n")

  if Object.const_defined?(:Time)
    t_time = Time.now - $test_start
    t_print(" Time: #{t_time.round(2)} seconds\n")
  end
end

##
# Performs fuzzy check for equality on methods returning floats
def check_float(a, b)
  tolerance = Mrbtest::FLOAT_TOLERANCE
  a = a.to_f
  b = b.to_f
  if a.finite? and b.finite?
    (a-b).abs < tolerance
  else
    true
  end
end

##
# Skip the test
class MRubyTestSkip < NotImplementedError
  attr_accessor :cause
  def initialize(cause)
    @cause = cause
  end
end

def skip(cause = "")
  raise MRubyTestSkip.new(cause)
end
