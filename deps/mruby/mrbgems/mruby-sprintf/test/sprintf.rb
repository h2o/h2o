#assert('Kernel.sprintf') do
#end

assert('String#%') do
  assert_equal "one=1", "one=%d" % 1
  assert_equal "1 one", "%d %s" % [ 1, "one" ]
  assert_equal "1.0", "%3.1f" % 1.01 if class_defined?("Float")
  assert_equal "123 < 456", "%{num} < %<str>s" % { num: 123, str: "456" }
  assert_equal 15, ("%b" % (1<<14)).size
end

assert('String#% with inf') do
  inf = Float::INFINITY

  assert_equal "Inf", "%f" % inf
  assert_equal "Inf", "%2f" % inf
  assert_equal "Inf", "%3f" % inf
  assert_equal " Inf", "%4f" % inf
  assert_equal "  Inf", "%5f" % inf

  assert_equal "+Inf", "%+f" % inf
  assert_equal "+Inf", "%+2f" % inf
  assert_equal "+Inf", "%+3f" % inf
  assert_equal "+Inf", "%+4f" % inf
  assert_equal " +Inf", "%+5f" % inf

  assert_equal "Inf", "%-f" % inf
  assert_equal "Inf", "%-2f" % inf
  assert_equal "Inf", "%-3f" % inf
  assert_equal "Inf ", "%-4f" % inf
  assert_equal "Inf  ", "%-5f" % inf

  assert_equal " Inf", "% f" % inf
  assert_equal " Inf", "% 2f" % inf
  assert_equal " Inf", "% 3f" % inf
  assert_equal " Inf", "% 4f" % inf
  assert_equal "  Inf", "% 5f" % inf
end if class_defined?("Float")

assert('String#% with nan') do
  nan = Float::NAN

  assert_equal "NaN", "%f" % nan
  assert_equal "NaN", "%2f" % nan
  assert_equal "NaN", "%3f" % nan
  assert_equal " NaN", "%4f" % nan
  assert_equal "  NaN", "%5f" % nan

  assert_equal "+NaN", "%+f" % nan
  assert_equal "+NaN", "%+2f" % nan
  assert_equal "+NaN", "%+3f" % nan
  assert_equal "+NaN", "%+4f" % nan
  assert_equal " +NaN", "%+5f" % nan

  assert_equal "NaN", "%-f" % nan
  assert_equal "NaN", "%-2f" % nan
  assert_equal "NaN", "%-3f" % nan
  assert_equal "NaN ", "%-4f" % nan
  assert_equal "NaN  ", "%-5f" % nan

  assert_equal " NaN", "% f" % nan
  assert_equal " NaN", "% 2f" % nan
  assert_equal " NaN", "% 3f" % nan
  assert_equal " NaN", "% 4f" % nan
  assert_equal "  NaN", "% 5f" % nan
end if class_defined?("Float")

assert("String#% with invalid chr") do
  begin
    class Fixnum
      alias_method :chr_, :chr if method_defined?(:chr)

      def chr
        nil
      end
    end

    assert_raise TypeError do
      "%c" % 0x80
    end
  ensure
    class Fixnum
      if method_defined?(:chr_)
        alias_method :chr, :chr_
        remove_method :chr_
      end
    end
  end
end

assert("String#% %b") do
  assert_equal("..10115", "%0b5" % -5)
end

assert("String#% %d") do
  assert_equal("  10",   "%4d" % 10)
  assert_equal("1000",   "%4d" % 1000)
  assert_equal("10000",  "%4d" % 10000)
end

assert("String#% invalid format") do
  assert_raise ArgumentError do
    "%?" % ""
  end
end

assert("String#% invalid format shared substring") do
  fmt = ("x"*30+"%!")[0...-1]
  assert_equal fmt, sprintf(fmt, "")
end
