class Complex < Numeric
  def self.polar(abs, arg = 0)
    Complex(abs * Math.cos(arg), abs * Math.sin(arg))
  end

  def inspect
    "(#{to_s})"
  end

  def to_s
    "#{real}#{'+' unless imaginary < 0}#{imaginary}#{'*' unless imaginary.finite?}i"
  end

  def +@
    self
  end

  def -@
    Complex(-real, -imaginary)
  end

  def abs
    Math.hypot imaginary, real
  end
  alias_method :magnitude, :abs

  def abs2
    real * real + imaginary * imaginary
  end

  def arg
    Math.atan2 imaginary, real
  end
  alias_method :angle, :arg
  alias_method :phase, :arg

  def conjugate
    Complex(real, -imaginary)
  end
  alias_method :conj, :conjugate

  def fdiv(numeric)
    Complex(real / numeric, imaginary / numeric)
  end

  def polar
    [abs, arg]
  end

  def real?
    false
  end

  def rectangular
    [real, imaginary]
  end
  alias_method :rect, :rectangular

  def to_c
    self
  end

  def to_r
    raise RangeError.new "can't convert #{to_s} into Rational" unless imaginary.zero?
    Rational(real, 1)
  end

  alias_method :imag, :imaginary

  Numeric.class_eval do
    def i
      Complex(0, self)
    end
  end
  undef i
end
