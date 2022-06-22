class Rational < Numeric
  def inspect
    "(#{to_s})"
  end

  def to_s
    "#{numerator}/#{denominator}"
  end

  def *(rhs)
    if rhs.is_a? Rational
      Rational(numerator * rhs.numerator, denominator * rhs.denominator)
    elsif rhs.is_a? Integer
      Rational(numerator * rhs, denominator)
    elsif rhs.is_a? Numeric
      numerator * rhs / denominator
    end
  end

  def +(rhs)
    if rhs.is_a? Rational
      Rational(numerator * rhs.denominator + rhs.numerator * denominator, denominator * rhs.denominator)
    elsif rhs.is_a? Integer
      Rational(numerator + rhs * denominator, denominator)
    elsif rhs.is_a? Numeric
      (numerator + rhs * denominator) / denominator
    end
  end

  def -(rhs)
    if rhs.is_a? Rational
      Rational(numerator * rhs.denominator - rhs.numerator * denominator, denominator * rhs.denominator)
    elsif rhs.is_a? Integer
      Rational(numerator - rhs * denominator, denominator)
    elsif rhs.is_a? Numeric
      (numerator - rhs * denominator) / denominator
    end
  end

  def /(rhs)
    if rhs.is_a? Rational
      Rational(numerator * rhs.denominator, denominator * rhs.numerator)
    elsif rhs.is_a? Integer
      Rational(numerator, denominator * rhs)
    elsif rhs.is_a? Numeric
      numerator / rhs / denominator
    end
  end

  alias quo /

  def <=>(rhs)
    case rhs
    when Integer, Float
      return numerator <=> rhs if denominator == 1
      rhs = Rational(rhs)
    end
    case rhs
    when Rational
      (numerator * rhs.denominator - denominator * rhs.numerator) <=> 0
    when Numeric
      (rhs <=> self)&.-@
    else
      nil
    end
  end

  def ==(rhs)
    return true if self.equal?(rhs)
    case rhs
    when Integer, Float
      return numerator == rhs if denominator == 1
    when Rational
      return numerator * rhs.denominator == denominator * rhs.numerator
    end
    rhs == self
  end
end

class Numeric
  def to_r
    Rational(self, 1)
  end
end

module Kernel
  [:+, :-, :*, :/, :<=>, :==, :<, :<=, :>, :>=].each do |op|
    original_operator_name = :"__original_operator_#{op}_rational"
    Integer.instance_eval do
      alias_method original_operator_name, op
      define_method op do |rhs|
        if rhs.is_a? Rational
          Rational(self).__send__(op, rhs)
        else
          __send__(original_operator_name, rhs)
        end
      end
    end
    Float.instance_eval do
      alias_method original_operator_name, op
      define_method op do |rhs|
        if rhs.is_a? Rational
          rhs = rhs.to_f
        end
        __send__(original_operator_name, rhs)
      end
    end if Object.const_defined?(:Float)
  end
end
