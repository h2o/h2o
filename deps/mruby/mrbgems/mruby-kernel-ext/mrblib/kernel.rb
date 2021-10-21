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
end
