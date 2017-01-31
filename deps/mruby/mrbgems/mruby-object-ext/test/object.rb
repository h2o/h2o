assert('Object#instance_exec') do
  class KlassWithSecret
    def initialize
      @secret = 99
    end
  end
  k = KlassWithSecret.new
  assert_equal 104, k.instance_exec(5) {|x| @secret+x }
end

assert('Object#tap') do
  ret = []
  (1..10)                 .tap {|x| ret << "original: #{x.inspect}"}
     .to_a                .tap {|x| ret << "array: #{x.inspect}"}
     .select {|x| x%2==0} .tap {|x| ret << "evens: #{x.inspect}"}
     .map { |x| x*x }     .tap {|x| ret << "squares: #{x.inspect}"}

  assert_equal [
    "original: 1..10",
    "array: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]",
    "evens: [2, 4, 6, 8, 10]",
    "squares: [4, 16, 36, 64, 100]"
  ], ret
  assert_equal(:tap_ok, Class.new {def m; tap{return :tap_ok}; end}.new.m)
end

assert('instance_exec on primitives with class and module definition') do
  begin
    class A
      1.instance_exec do
        class B
        end
      end
    end

    assert_kind_of Class, A::B
  ensure
    Object.remove_const :A
  end

  begin
    class A
      1.instance_exec do
        module B
        end
      end
    end

    assert_kind_of Module, A::B
  ensure
    Object.remove_const :A
  end
end
