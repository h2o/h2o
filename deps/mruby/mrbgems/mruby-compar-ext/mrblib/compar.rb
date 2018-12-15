module Comparable
  ##
  # Returns <i>min</i> if <i>obj</i> <code><=></code> <i>min</i> is less
  # than zero, <i>max</i> if <i>obj</i> <code><=></code> <i>max</i> is
  # greater than zero and <i>obj</i> otherwise.
  #
  #     12.clamp(0, 100)         #=> 12
  #     523.clamp(0, 100)        #=> 100
  #     -3.123.clamp(0, 100)     #=> 0
  #
  #     'd'.clamp('a', 'f')      #=> 'd'
  #     'z'.clamp('a', 'f')      #=> 'f'
  #
  def clamp(min, max)
    if (min <=> max) > 0
      raise ArgumentError, "min argument must be smaller than max argument"
    end
    c = self <=> min
    if c == 0
      return self
    elsif c < 0
      return min
    end
    c = self <=> max
    if c > 0
      return max
    else
      return self
    end
  end
end
