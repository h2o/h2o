module Kernel
  # call-seq:
  #   obj.yield_self {|_obj|...} -> an_object
  #   obj.then {|_obj|...}       -> an_object
  #
  # Yields <i>obj</i> and returns the result.
  #
  #   'my string'.yield_self {|s|s.upcase} #=> "MY STRING"
  #
  def yield_self(&block)
    return to_enum :yield_self unless block
    block.call(self)
  end
  alias then yield_self

  ##
  #  call-seq:
  #     obj.tap{|x|...}    -> obj
  #
  #  Yields <code>x</code> to the block, and then returns <code>x</code>.
  #  The primary purpose of this method is to "tap into" a method chain,
  #  in order to perform operations on intermediate results within the chain.
  #
  #  (1..10)                .tap {|x| puts "original: #{x.inspect}"}
  #    .to_a                .tap {|x| puts "array: #{x.inspect}"}
  #    .select {|x| x%2==0} .tap {|x| puts "evens: #{x.inspect}"}
  #    .map { |x| x*x }     .tap {|x| puts "squares: #{x.inspect}"}
  #
  def tap
    yield self
    self
  end
end
