class Numeric
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

  def positive?
    self > 0
  end

  def negative?
    self < 0
  end
end
