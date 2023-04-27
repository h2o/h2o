##
# Math Test

def assert_float_and_int(exp_ary, act_ary)
  assert('assert_float_and_int') do
    flo_exp, int_exp, flo_act, int_act = *exp_ary, *act_ary
    assert_float(flo_exp, flo_act)
    assert_operator(int_exp, :eql?, int_act)
  end
end

assert('Math.sin') do
  assert_float(0, Math.sin(0))
  assert_float(1, Math.sin(Math::PI / 2))
end

assert('Math.cos') do
  assert_float(1, Math.cos(0))
  assert_float(0, Math.cos(Math::PI / 2))
end

assert('Math.tan') do
  assert_float(0, Math.tan(0))
  assert_float(1, Math.tan(Math::PI / 4))
end

assert('Fundamental trig identities') do
  N = 13
  N.times do |i|
    a  = Math::PI / N * i
    ca = Math::PI / 2 - a
    s  = Math.sin(a)
    c  = Math.cos(a)
    t  = Math.tan(a)
    assert_float(Math.cos(ca), s)
    assert_float(1 / Math.tan(ca), t)
    assert_float(1, s ** 2 + c ** 2)
    assert_float((1/c) ** 2, t ** 2 + 1)
    assert_float((1/s) ** 2, (1/t) ** 2 + 1)
  end
end

assert('Math.exp') do
  assert_float(1.0, Math.exp(0))
  assert_float(2.718281828459045, Math.exp(1))
  assert_float(4.4816890703380645, Math.exp(1.5))
end

assert('Math.log') do
  assert_float(0, Math.log(1))
  assert_float(1.0, Math.log(Math::E))
  assert_float(3.0, Math.log(Math::E**3))
end

assert('Math.log2') do
  assert_float(0.0, Math.log2(1))
  assert_float(1.0, Math.log2(2))
end

assert('Math.log10') do
  assert_float(0.0, Math.log10(1))
  assert_float(1.0, Math.log10(10))
  assert_float(30.0, Math.log10(10.0**30))
end

assert('Math.sqrt') do
  num = [0.0, 1.0, 2.0, 3.0, 4.0]
  sqr = [0, 1, 4, 9, 16]
  sqr.each_with_index do |v,i|
    assert_float(num[i], Math.sqrt(v))
  end
end

assert('Math.cbrt') do
  num = [-2.0, -1.0, 0.0, 1.0, 2.0]
  cub = [-8, -1, 0, 1, 8]
  cub.each_with_index do |v,i|
    assert_float(num[i], Math.cbrt(v))
  end
end

assert('Math.hypot') do
  assert_float(5.0, Math.hypot(3, 4))
end

assert('Math.erf') do
  assert_float(0, Math.erf(0))
  assert_float(0.842700792949715, Math.erf(1))
  assert_float(-0.8427007929497148, Math.erf(-1))
end

assert('Math.erfc') do
  assert_float(0.157299207050285, Math.erfc(1))
  assert_float(1.8427007929497148, Math.erfc(-1))
end

assert('Math.acos') do
  assert_float(0 * Math::PI / 4, Math.acos( 1.0))
  assert_float(1 * Math::PI / 4, Math.acos( 1.0 / Math.sqrt(2)))
  assert_float(2 * Math::PI / 4, Math.acos( 0.0))
  assert_float(4 * Math::PI / 4, Math.acos(-1.0))
  assert_raise(Math::DomainError) { Math.acos(+1.1) }
  assert_raise(Math::DomainError) { Math.acos(-1.1) }
end

assert('Math.asin') do
  assert_float( 0 * Math::PI / 4, Math.asin( 0.0))
  assert_float( 1 * Math::PI / 4, Math.asin( 1.0 / Math.sqrt(2)))
  assert_float( 2 * Math::PI / 4, Math.asin( 1.0))
  assert_float(-2 * Math::PI / 4, Math.asin(-1.0))
  assert_raise(Math::DomainError) { Math.asin(+1.1) }
  assert_raise(Math::DomainError) { Math.asin(-1.1) }
  assert_raise(Math::DomainError) { Math.asin(2.0) }
end

assert('Math.atan') do
  assert_float( 0 * Math::PI / 4, Math.atan( 0.0))
  assert_float( 1 * Math::PI / 4, Math.atan( 1.0))
  assert_float( 2 * Math::PI / 4, Math.atan(1.0 / 0.0))
  assert_float(-1 * Math::PI / 4, Math.atan(-1.0))
end

assert('Math.cosh') do
  assert_float(1, Math.cosh(0))
  assert_float((Math::E ** 1 + Math::E ** -1) / 2, Math.cosh(1))
  assert_float((Math::E ** 2 + Math::E ** -2) / 2, Math.cosh(2))
end

assert('Math.sinh') do
  assert_float(0, Math.sinh(0))
  assert_float((Math::E ** 1 - Math::E ** -1) / 2, Math.sinh(1))
  assert_float((Math::E ** 2 - Math::E ** -2) / 2, Math.sinh(2))
end

assert('Math.tanh') do
  assert_float(Math.sinh(0) / Math.cosh(0), Math.tanh(0))
  assert_float(Math.sinh(1) / Math.cosh(1), Math.tanh(1))
  assert_float(Math.sinh(2) / Math.cosh(2), Math.tanh(2))
  assert_float(+1.0, Math.tanh(+1000.0))
  assert_float(-1.0, Math.tanh(-1000.0))
end

assert('Math.acosh') do
  assert_float(0, Math.acosh(1))
  assert_float(1, Math.acosh((Math::E ** 1 + Math::E ** -1) / 2))
  assert_float(2, Math.acosh((Math::E ** 2 + Math::E ** -2) / 2))
  assert_raise(Math::DomainError) { Math.acosh(0.9) }
  assert_raise(Math::DomainError) { Math.acosh(0) }
end

assert('Math.asinh') do
  assert_float(0, Math.asinh(0))
  assert_float(1, Math.asinh((Math::E ** 1 - Math::E ** -1) / 2))
  assert_float(2, Math.asinh((Math::E ** 2 - Math::E ** -2) / 2))
end

assert('Math.atanh') do
  assert_float(0, Math.atanh(Math.sinh(0) / Math.cosh(0)))
  assert_float(1, Math.atanh(Math.sinh(1) / Math.cosh(1)))
  assert_float(2, Math.atanh(Math.sinh(2) / Math.cosh(2)))
  assert_float(Float::INFINITY, Math.atanh(1))
  assert_float(-Float::INFINITY, Math.atanh(-1))
  assert_raise(Math::DomainError) { Math.atanh(+1.1) }
  assert_raise(Math::DomainError) { Math.atanh(-1.1) }
end

assert('Math.atan2') do
  assert_float(+0.0, Math.atan2(+0.0, +0.0))
  assert_float(-0.0, Math.atan2(-0.0, +0.0))
  assert_float(+Math::PI, Math.atan2(+0.0, -0.0))
  assert_float(-Math::PI, Math.atan2(-0.0, -0.0))

  assert_float(0, Math.atan2(0, 1))
  assert_float(Math::PI / 4, Math.atan2(1, 1))
  assert_float(Math::PI / 2, Math.atan2(1, 0))

  inf = Float::INFINITY
  skip "Math.atan2() return NaN" if Math.atan2(+inf, -inf).nan?
  expected = 3.0 * Math::PI / 4.0
  assert_float(+expected, Math.atan2(+inf, -inf))
  assert_float(-expected, Math.atan2(-inf, -inf))
  expected = Math::PI / 4.0
  assert_float(+expected, Math.atan2(+inf, +inf))
  assert_float(-expected, Math.atan2(-inf, +inf))
end

assert('Math.ldexp') do
  assert_float(0.0, Math.ldexp(0.0, 0.0))
  assert_float(0.5, Math.ldexp(0.5, 0.0))
  assert_float(1.0, Math.ldexp(0.5, 1.0))
  assert_float(2.0, Math.ldexp(0.5, 2.0))
  assert_float(3.0, Math.ldexp(0.75, 2.0))
end

assert('Math.frexp') do
  assert_float_and_int([0.0,  0], Math.frexp(0.0))
  assert_float_and_int([0.5,  0], Math.frexp(0.5))
  assert_float_and_int([0.5,  1], Math.frexp(1.0))
  assert_float_and_int([0.5,  2], Math.frexp(2.0))
  assert_float_and_int([0.75, 2], Math.frexp(3.0))
end
