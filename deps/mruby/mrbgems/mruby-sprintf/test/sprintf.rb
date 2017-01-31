#assert('Kernel.sprintf') do
#end

assert('String#%') do
  assert_equal "one=1", "one=%d" % 1
  assert_equal "1 one 1.0", "%d %s %3.1f" % [ 1, "one", 1.01 ]
  assert_equal "123 < 456", "%{num} < %<str>s" % { num: 123, str: "456" }
  assert_equal 15, ("%b" % (1<<14)).size
end

assert("String#% with invalid chr") do
  begin
    class Fixnum
      alias_method :chr_, :chr if method_defined?(:chr)

      def chr
        nil
      end
    end

    assert_raise TypeError do
      "%c" % 0
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
