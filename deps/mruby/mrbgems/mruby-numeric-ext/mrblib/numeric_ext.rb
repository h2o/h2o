module Integral
  def div(other)
    self.divmod(other)[0]
  end

  def zero?
    self == 0
  end

  def nonzero?
    if self == 0
      nil
    else
      self
    end
  end
end
