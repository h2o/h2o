class Rational < Numeric
  def inspect
    "(#{to_s})"
  end

  def to_s
    "#{numerator}/#{denominator}"
  end
end

class Numeric
  def to_r
    Rational(self, 1)
  end
end
