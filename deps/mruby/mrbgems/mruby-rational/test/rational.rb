class UserDefinedNumeric < Numeric
  def initialize(n)
    @n = n
  end

  def <=>(rhs)
    return nil unless rhs.respond_to?(:to_i)
    rhs = rhs.to_i
    rhs < 0 ? nil : @n <=> rhs
  end

  def inspect
    "#{self.class}(#{@n})"
  end
end

class ComplexLikeNumeric < UserDefinedNumeric
  def ==(rhs)
    @n == 0 && rhs == 0
  end

  undef <=>
end

def assert_rational(exp, real)
  assert "assert_rational" do
    assert_kind_of Rational, real
    assert_float exp.numerator,   real.numerator
    assert_float exp.denominator, real.denominator
  end
end

def assert_equal_rational(exp, o1, o2)
  assert "assert_equal_rational" do
    if exp
      assert_operator(o1, :==, o2)
      assert_not_operator(o1, :!=, o2)
    else
      assert_not_operator(o1, :==, o2)
      assert_operator(o1, :!=, o2)
    end
  end
end

def assert_cmp(exp, o1, o2)
  if exp == (o1 <=> o2)
    pass
  else
    flunk "", "    Expected #{o1.inspect} <=> #{o2.inspect} to be #{exp}."
  end
end

def assert_complex(real, imag)
  if Object.const_defined?(:Complex)
    assert "assert_complex" do
      c = yield
      assert_float(real, c.real)
      assert_float(imag, c.imaginary)
    end
  end
end

assert 'Rational' do
  r = 5r
  assert_equal(Rational, r.class)
  assert_equal([5, 1], [r.numerator, r.denominator])
end

assert 'Kernel#Rational' do
  r = Rational(4,10)
  assert_equal(2, r.numerator)
  assert_equal(5, r.denominator)

  r = Rational(3)
  assert_equal(3, r.numerator)
  assert_equal(1, r.denominator)

  assert_raise(ArgumentError) { Rational() }
  assert_raise(ArgumentError) { Rational(1,2,3) }
end

assert 'Rational#to_f' do
  assert_float(2.0, Rational(2).to_f)
  assert_float(2.25, Rational(9, 4).to_f)
  assert_float(-0.75, Rational(-3, 4).to_f)
  assert_float(6.666666666666667, Rational(20, 3).to_f)
end

assert 'Rational#to_i' do
  assert_equal(0, Rational(2, 3).to_i)
  assert_equal(3, Rational(3).to_i)
  assert_equal(300, Rational(300.6).to_i)
  assert_equal(1, Rational(98, 71).to_i)
  assert_equal(-15, Rational(-30, 2).to_i)
end

assert 'Rational#*' do
  assert_rational(Rational(4, 9),    Rational(2, 3)  * Rational(2, 3))
  assert_rational(Rational(900, 1),  Rational(900)   * Rational(1))
  assert_rational(Rational(1, 1),    Rational(-2, 9) * Rational(-9, 2))
  assert_rational(Rational(9, 2),    Rational(9, 8)  * 4)
  assert_float(   21.77777777777778, Rational(20, 9) * 9.8)
  assert_float(   21.77777777777778, 9.8 * Rational(20, 9))
  assert_complex(5.2, 2.6) {Rational(13,5)*(2.0+1i)}
  assert_complex(5.2, 2.6) {(2.0+1i)*Rational(13,5)}
end

assert 'Rational#+' do
  assert_rational(Rational(4, 3),     Rational(2, 3)  + Rational(2, 3))
  assert_rational(Rational(901, 1),   Rational(900)   + Rational(1))
  assert_rational(Rational(-85, 18),  Rational(-2, 9) + Rational(-9, 2))
  assert_rational(Rational(41, 8),    Rational(9, 8)  + 4)
  assert_rational(Rational(41, 8),    4 + Rational(9, 8))
  assert_float(   12.022222222222222, Rational(20, 9) + 9.8)
  assert_float(   12.022222222222222, 9.8 + Rational(20, 9))
  assert_complex(24.0, 0) {Rational(24,2)+(12.0+0i)}
  assert_complex(24.0, 0) {(12.0+0i)+Rational(24,2)}
end

assert 'Rational#-' do
  assert_rational(Rational(0, 1),     Rational(2, 3)  - Rational(2, 3))
  assert_rational(Rational(899, 1),   Rational(900)   - Rational(1))
  assert_rational(Rational(77, 18),   Rational(-2, 9) - Rational(-9, 2))
  assert_rational(Rational(23, 8),    4 - Rational(9, 8))
  assert_float(   -7.577777777777778, Rational(20, 9) - 9.8)
  assert_float(    7.577777777777778, 9.8 - Rational(20, 9))
  assert_complex(2.0, 0) {Rational(24,2)-(10.0+0i)}
  assert_complex(2.0, 0) {(14.0+0i)-Rational(24,2)}
end

assert 'Rational#/' do
  assert_rational(Rational(1, 1),      Rational(2, 3)  / Rational(2, 3))
  assert_rational(Rational(900, 1),    Rational(900)   / Rational(1))
  assert_rational(Rational(4, 81),     Rational(-2, 9) / Rational(-9, 2))
  assert_rational(Rational(9, 32),     Rational(9, 8)  / 4)
  assert_rational(Rational(32, 9),     4 / Rational(9, 8))
  assert_float(   0.22675736961451246, Rational(20, 9) / 9.8)
  assert_float(   4.41,                9.8 / Rational(20, 9))
  assert_complex(1.92, 1.44) {Rational(24,2)/(4.0-3i)}
  assert_complex(0.25, 0.25) {(3.0+3i)/Rational(24,2)}
end

assert 'Rational#==, Rational#!=' do
  assert_equal_rational(true, Rational(1,1), Rational(1))
  assert_equal_rational(true, Rational(-1,1), -1r)
  assert_equal_rational(true, Rational(13,4), 3.25)
  assert_equal_rational(true, Rational(13,3.25), Rational(4,1))
  assert_equal_rational(true, Rational(-3,-4), Rational(3,4))
  assert_equal_rational(true, Rational(-4,5), Rational(4,-5))
  assert_equal_rational(true, Rational(4,2), 2)
  assert_equal_rational(true, Rational(-4,2), -2)
  assert_equal_rational(true, Rational(4,-2), -2)
  assert_equal_rational(true, Rational(4,2), 2.0)
  assert_equal_rational(true, Rational(-4,2), -2.0)
  assert_equal_rational(true, Rational(4,-2), -2.0)
  assert_equal_rational(true, Rational(8,6), Rational(4,3))
  assert_equal_rational(false, Rational(13,4), 3)
  assert_equal_rational(false, Rational(13,4), 3.3)
  assert_equal_rational(false, Rational(2,1), 1r)
  assert_equal_rational(false, Rational(1), nil)
  assert_equal_rational(false, Rational(1), '')
  assert_equal_rational(true, 0r, UserDefinedNumeric.new(0))
  assert_equal_rational(true, 1r, UserDefinedNumeric.new(1))
  assert_equal_rational(false, 1r, UserDefinedNumeric.new(2))
  assert_equal_rational(false, -1r, UserDefinedNumeric.new(-1))
  assert_equal_rational(true, 0r, ComplexLikeNumeric.new(0))
  assert_equal_rational(false, 1r, ComplexLikeNumeric.new(1))
  assert_equal_rational(false, 1r, ComplexLikeNumeric.new(2))
end

assert 'Integer#==(Rational), Integer#!=(Rational)' do
  assert_equal_rational(true, 2, Rational(4,2))
  assert_equal_rational(true, -2, Rational(-4,2))
  assert_equal_rational(true, -2, Rational(4,-2))
  assert_equal_rational(false, 3, Rational(13,4))
end

assert 'Float#==(Rational), Float#!=(Rational)' do
  assert_equal_rational(true, 2.0, Rational(4,2))
  assert_equal_rational(true, -2.0, Rational(-4,2))
  assert_equal_rational(true, -2.0, Rational(4,-2))
  assert_equal_rational(false, 3.3, Rational(13,4))
end

assert 'Rational#<=>' do
  assert_cmp(-1, Rational(-1), Rational(0))
  assert_cmp(0, Rational(0), Rational(0))
  assert_cmp(1, Rational(1), Rational(0))
  assert_cmp(-1, Rational(-1), 0)
  assert_cmp(0, Rational(0), 0)
  assert_cmp(1, Rational(1), 0)
  assert_cmp(-1, Rational(-1), 0.0)
  assert_cmp(0, Rational(0), 0.0)
  assert_cmp(1, Rational(1), 0.0)
  assert_cmp(-1, Rational(1,2), Rational(2,3))
  assert_cmp(0, Rational(2,3), Rational(2,3))
  assert_cmp(1, Rational(2,3), Rational(1,2))
  assert_cmp(1, Rational(2,3), Rational(1,2))
  assert_cmp(1, Rational(0), Rational(-1))
  assert_cmp(-1, Rational(0), Rational(1))
  assert_cmp(1, Rational(2,3), Rational(1,2))
  assert_cmp(0, Rational(2,3), Rational(2,3))
  assert_cmp(-1, Rational(1,2), Rational(2,3))
  assert_cmp(-1, Rational(1,2), Rational(2,3))
  assert_cmp(nil, 3r, "3")
  assert_cmp(1, 3r, UserDefinedNumeric.new(2))
  assert_cmp(0, 3r, UserDefinedNumeric.new(3))
  assert_cmp(-1, 3r, UserDefinedNumeric.new(4))
  assert_cmp(nil, Rational(-3), UserDefinedNumeric.new(5))
  assert_raise(NoMethodError) { 0r <=> ComplexLikeNumeric.new(0) }
  assert_raise(NoMethodError) { 1r <=> ComplexLikeNumeric.new(2) }
end

assert 'Integer#<=>(Rational)' do
  assert_cmp(-1, -2, Rational(-9,5))
  assert_cmp(0, 5, 5r)
  assert_cmp(1, 3, Rational(8,3))
end

assert 'Float#<=>(Rational)' do
  assert_cmp(-1, -2.1, Rational(-9,5))
  assert_cmp(0, 5.0, 5r)
  assert_cmp(1, 2.7, Rational(8,3))
end

assert 'Rational#<' do
  assert_operator(Rational(1,2), :<, Rational(2,3))
  assert_not_operator(Rational(2,3), :<, Rational(2,3))
  assert_operator(Rational(2,3), :<, 1)
  assert_not_operator(2r, :<, 2)
  assert_not_operator(Rational(2,3), :<, -3)
  assert_operator(Rational(-4,3), :<, -0.3)
  assert_not_operator(Rational(13,4), :<, 3.25)
  assert_not_operator(Rational(2,3), :<, 0.6)
  assert_raise(ArgumentError) { 1r < "2" }
end

assert 'Integer#<(Rational)' do
  assert_not_operator(1, :<, Rational(2,3))
  assert_not_operator(2, :<, 2r)
  assert_operator(-3, :<, Rational(2,3))
end

assert 'Float#<(Rational)' do
  assert_not_operator(-0.3, :<, Rational(-4,3))
  assert_not_operator(3.25, :<, Rational(13,4))
  assert_operator(0.6, :<, Rational(2,3))
end

assert 'Rational#<=' do
  assert_operator(Rational(1,2), :<=, Rational(2,3))
  assert_operator(Rational(2,3), :<=, Rational(2,3))
  assert_operator(Rational(2,3), :<=, 1)
  assert_operator(2r, :<=, 2)
  assert_not_operator(Rational(2,3), :<=, -3)
  assert_operator(Rational(-4,3), :<=, -0.3)
  assert_operator(Rational(13,4), :<=, 3.25)
  assert_not_operator(Rational(2,3), :<=, 0.6)
  assert_raise(ArgumentError) { 1r <= "2" }
end

assert 'Integer#<=(Rational)' do
  assert_not_operator(1, :<=, Rational(2,3))
  assert_operator(2, :<=, 2r)
  assert_operator(-3, :<=, Rational(2,3))
end

assert 'Float#<=(Rational)' do
  assert_not_operator(-0.3, :<=, Rational(-4,3))
  assert_operator(3.25, :<=, Rational(13,4))
  assert_operator(0.6, :<=, Rational(2,3))
end

assert 'Rational#>' do
  assert_not_operator(Rational(1,2), :>, Rational(2,3))
  assert_not_operator(Rational(2,3), :>, Rational(2,3))
  assert_not_operator(Rational(2,3), :>, 1)
  assert_not_operator(2r, :>, 2)
  assert_operator(Rational(2,3), :>, -3)
  assert_not_operator(Rational(-4,3), :>, -0.3)
  assert_not_operator(Rational(13,4), :>, 3.25)
  assert_operator(Rational(2,3), :>, 0.6)
  assert_raise(ArgumentError) { 1r > "2" }
end

assert 'Integer#>(Rational)' do
  assert_operator(1, :>, Rational(2,3))
  assert_not_operator(2, :>, 2r)
  assert_not_operator(-3, :>, Rational(2,3))
end

assert 'Float#>(Rational)' do
  assert_operator(-0.3, :>, Rational(-4,3))
  assert_not_operator(3.25, :>, Rational(13,4))
  assert_not_operator(0.6, :>, Rational(2,3))
end

assert 'Rational#>=' do
  assert_not_operator(Rational(1,2), :>=, Rational(2,3))
  assert_operator(Rational(2,3), :>=, Rational(2,3))
  assert_not_operator(Rational(2,3), :>=, 1)
  assert_operator(2r, :>=, 2)
  assert_operator(Rational(2,3), :>=, -3)
  assert_not_operator(Rational(-4,3), :>=, -0.3)
  assert_operator(Rational(13,4), :>=, 3.25)
  assert_operator(Rational(2,3), :>=, 0.6)
  assert_raise(ArgumentError) { 1r >= "2" }
end

assert 'Integer#>=(Rational)' do
  assert_operator(1, :>=, Rational(2,3))
  assert_operator(2, :>=, 2r)
  assert_not_operator(-3, :>=, Rational(2,3))
end

assert 'Float#>=(Rational)' do
  assert_operator(-0.3, :>=, Rational(-4,3))
  assert_operator(3.25, :>=, Rational(13,4))
  assert_not_operator(0.6, :>=, Rational(2,3))
end

assert 'Rational#negative?' do
  assert_predicate(Rational(-2,3), :negative?)
  assert_predicate(Rational(2,-3), :negative?)
  assert_not_predicate(Rational(2,3), :negative?)
  assert_not_predicate(Rational(0), :negative?)
end

assert 'Rational#frozen?' do
  assert_predicate(1r, :frozen?)
  assert_predicate(Rational(2,3), :frozen?)
  assert_predicate(4/5r, :frozen?)
end
