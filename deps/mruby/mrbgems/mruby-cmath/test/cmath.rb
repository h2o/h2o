##
# CMath Test

def assert_complex(c1, c2)
  assert('assert_complex') do
    assert_float(c1.real, c2.real)
    assert_float(c1.imaginary, c2.imaginary)
  end
end

assert('CMath.exp') do
  assert_float(1.0, CMath.exp(0))
  assert_complex(-1+0i, CMath.exp(Math::PI.i))
  assert_complex((-1.1312043837568135+2.4717266720048188i), CMath.exp(1+2i))
end

assert('CMath.log') do
  assert_float(0, CMath.log(1))
  assert_float(3.0, CMath.log(8,2))
  assert_complex((1.092840647090816-0.42078724841586035i), CMath.log(-8,-2))
end

assert('CMath.sqrt') do
  assert_complex(Complex(0,2), CMath.sqrt(-4.0))
  assert_complex(Complex(0,3), CMath.sqrt(-9.0))
end

assert('CMath trigonometric_functions') do
  assert_complex(Math.sinh(2).i, CMath.sin(2i))
  assert_complex(Math.cosh(2)+0i,   CMath.cos(2i))
  assert_complex(Math.tanh(2).i, CMath.tan(2i))
  assert_complex(Math.sin(2).i, CMath.sinh(2i))
  assert_complex(Math.cos(2)+0i, CMath.cosh(2i))
  assert_complex(Math.tan(2).i, CMath.tanh(2i))
  assert_complex(1+1i, CMath.sin(CMath.asin(1+1i)))
  assert_complex(1+1i, CMath.cos(CMath.acos(1+1i)))
  assert_complex(1+1i, CMath.tan(CMath.atan(1+1i)))
  assert_complex(1+1i, CMath.sinh(CMath.asinh(1+1i)))
  assert_complex(1+1i, CMath.cosh(CMath.acosh(1+1i)))
  assert_complex(1+1i, CMath.tanh(CMath.atanh(1+1i)))
end
