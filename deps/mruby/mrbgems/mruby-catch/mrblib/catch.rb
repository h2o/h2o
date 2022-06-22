class ThrowCatchJump < Exception
  def initialize(tag, val)
    @tag = tag
    @val = val
    super("uncaught throw :#{tag}")
  end
  def _tag
    @tag
  end
  def _val
    @val
  end
end

module Kernel
  def catch(tag, &block)
    block.call(tag)
  rescue ThrowCatchJump => e
    unless e._tag == tag
      raise e
    end
    return e._val
  end
  def throw(tag, val=nil)
    raise ThrowCatchJump.new(tag, val)
  end
end
