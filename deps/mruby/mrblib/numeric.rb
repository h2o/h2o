##
# Numeric
#
# ISO 15.2.7
class Numeric
  include Comparable
  ##
  # Returns the receiver simply.
  #
  # ISO 15.2.7.4.1
  def +@
    self
  end

  ##
  # Returns the receiver's value, negated.
  #
  # ISO 15.2.7.4.2
  def -@
    0 - self
  end

  ##
  # Returns the absolute value of the receiver.
  #
  # ISO 15.2.7.4.3
  def abs
    if self < 0
      -self
    else
      self
    end
  end
end

##
# Integral
#
# mruby special - module to share methods between Floats and Integers
#                 to make them compatible
module Integral
  ##
  # Calls the given block once for each Integer
  # from +self+ downto +num+.
  #
  # ISO 15.2.8.3.15
  def downto(num, &block)
    return to_enum(:downto, num) unless block

    i = self.to_i
    while i >= num
      block.call(i)
      i -= 1
    end
    self
  end

  ##
  # Returns self + 1
  #
  # ISO 15.2.8.3.19
  def next
    self + 1
  end
  # ISO 15.2.8.3.21
  alias succ next

  ##
  # Calls the given block +self+ times.
  #
  # ISO 15.2.8.3.22
  def times &block
    return to_enum :times unless block

    i = 0
    while i < self
      block.call i
      i += 1
    end
    self
  end

  ##
  # Calls the given block once for each Integer
  # from +self+ upto +num+.
  #
  # ISO 15.2.8.3.27
  def upto(num, &block)
    return to_enum(:upto, num) unless block

    i = self.to_i
    while i <= num
      block.call(i)
      i += 1
    end
    self
  end

  ##
  # Calls the given block from +self+ to +num+
  # incremented by +step+ (default 1).
  #
  def step(num=nil, step=1, &block)
    raise ArgumentError, "step can't be 0" if step == 0
    return to_enum(:step, num, step) unless block

    i = if num.kind_of? Float then self.to_f else self end
    if num == nil
      while true
        block.call(i)
        i+=step
      end
      return self
    end
    if step > 0
      while i <= num
        block.call(i)
        i += step
      end
    else
      while i >= num
        block.call(i)
        i += step
      end
    end
    self
  end
end

##
# Integer
#
# ISO 15.2.8
class Integer
  include Integral
  ##
  # Returns the receiver simply.
  #
  # ISO 15.2.8.3.14
  def ceil
    self
  end

  ##
  # Returns the receiver simply.
  #
  # ISO 15.2.8.3.17
  def floor
    self
  end

  ##
  # Returns the receiver simply.
  #
  # ISO 15.2.8.3.24
  alias round floor

  ##
  # Returns the receiver simply.
  #
  # ISO 15.2.8.3.26
  alias truncate floor
end

##
# Float
#
# ISO 15.2.9
class Float
  # mruby special - since mruby integers may be upgraded to floats,
  # floats should be compatible to integers.
  include Integral
end
