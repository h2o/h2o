def assert_complex(real, exp)
  assert "assert_complex" do
    assert_float real.real,      exp.real
    assert_float real.imaginary, exp.imaginary
  end
end

assert 'Complex' do
  c = 123i
  assert_equal Complex, c.class
  assert_equal [c.real, c.imaginary], [0, 123]
  c = 123 + -1.23i
  assert_equal Complex, c.class
  assert_equal [c.real, c.imaginary], [123, -1.23]
end

assert 'Complex::polar' do
  assert_complex Complex.polar(3, 0),           (3  +  0i)
  assert_complex Complex.polar(3, Math::PI/2),  (0  +  3i)
  assert_complex Complex.polar(3, Math::PI),    (-3 +  0i)
  assert_complex Complex.polar(3, -Math::PI/2), (0  + -3i)
end

assert 'Complex::rectangular' do
  assert_complex Complex.rectangular(1, 2), (1 + 2i)
end

assert 'Complex#*' do
  assert_complex Complex(2, 3)  * Complex(2, 3),  (-5    + 12i)
  assert_complex Complex(900)   * Complex(1),     (900   + 0i)
  assert_complex Complex(-2, 9) * Complex(-9, 2), (0     - 85i)
  assert_complex Complex(9, 8)  * 4,              (36    + 32i)
  assert_complex Complex(20, 9) * 9.8,            (196.0 + 88.2i)
end

assert 'Complex#+' do
  assert_complex Complex(2, 3)  + Complex(2, 3) , (4    + 6i)
  assert_complex Complex(900)   + Complex(1)    , (901  + 0i)
  assert_complex Complex(-2, 9) + Complex(-9, 2), (-11  + 11i)
  assert_complex Complex(9, 8)  + 4             , (13   + 8i)
  assert_complex Complex(20, 9) + 9.8           , (29.8 + 9i)
end

assert 'Complex#-' do
  assert_complex Complex(2, 3)  - Complex(2, 3) , (0    + 0i)
  assert_complex Complex(900)   - Complex(1)    , (899  + 0i)
  assert_complex Complex(-2, 9) - Complex(-9, 2), (7    + 7i)
  assert_complex Complex(9, 8)  - 4             , (5    + 8i)
  assert_complex Complex(20, 9) - 9.8           , (10.2 + 9i)
end

assert 'Complex#-@' do
  assert_complex(-Complex(1, 2), (-1 - 2i))
end

assert 'Complex#/' do
  assert_complex Complex(2, 3)  / Complex(2, 3) , (1                  + 0i)
  assert_complex Complex(900)   / Complex(1)    , (900                + 0i)
  assert_complex Complex(-2, 9) / Complex(-9, 2), ((36 / 85)          - (77i / 85))
  assert_complex Complex(9, 8)  / 4             , ((9 / 4)            + 2i)
  assert_complex Complex(20, 9) / 9.8           , (2.0408163265306123 + 0.9183673469387754i)
  if 1e39.infinite? then
    # MRB_USE_FLOAT in effect
    ten = 1e21
    one = 1e20
  else
    ten = 1e201
    one = 1e200
  end
  assert_complex Complex(ten, ten) / Complex(one, one), Complex(10.0, 0.0)
end

assert 'Complex#==' do
  assert_true  Complex(2, 3)  == Complex(2, 3)
  assert_true  Complex(5)     == 5
  assert_true  Complex(0)     == 0.0
end

assert 'Complex#abs' do
  assert_float Complex(-1).abs,        1
  assert_float Complex(3.0, -4.0).abs, 5.0
  if 1e39.infinite? then
    # MRB_USE_FLOAT in effect
    exp = 125
  else
    exp = 1021
  end
  assert_true Complex(3.0*2.0**exp, 4.0*2.0**exp).abs.finite?
  assert_float Complex(3.0*2.0**exp, 4.0*2.0**exp).abs, 5.0*2.0**exp
end

assert 'Complex#abs2' do
  assert_float Complex(-1).abs2,        1
  assert_float Complex(3.0, -4.0).abs2, 25.0
end

assert 'Complex#arg' do
  assert_float Complex.polar(3, Math::PI/2).arg, 1.5707963267948966
end

assert 'Complex#conjugate' do
  assert_complex Complex(1, 2).conjugate, (1 - 2i)
end

assert 'Complex#fdiv' do
  assert_complex Complex(11, 22).fdiv(3), (3.6666666666666665 + 7.333333333333333i)
end

assert 'Complex#imaginary' do
  assert_float Complex(7).imaginary    , 0
  assert_float Complex(9, -4).imaginary, -4
end

assert 'Complex#polar' do
  assert_equal Complex(1, 2).polar, [2.23606797749979, 1.1071487177940904]
end

assert 'Complex#real' do
  assert_float Complex(7).real,     7
  assert_float Complex(9, -4).real, 9
end

assert 'Complex#real?' do
  assert_false Complex(1).real?
end

assert 'Complex::rectangular' do
  assert_equal Complex(1, 2).rectangular, [1, 2]
end

assert 'Complex::to_c' do
  assert_equal Complex(1, 2).to_c, Complex(1, 2)
end

assert 'Complex::to_f' do
  assert_float Complex(1, 0).to_f, 1.0
  assert_raise(RangeError) do
    Complex(1, 2).to_f
  end
end

assert 'Complex::to_i' do
  assert_equal Complex(1, 0).to_i, 1
  assert_raise(RangeError) do
    Complex(1, 2).to_i
  end
end

assert 'Complex#frozen?' do
  assert_predicate(1i, :frozen?)
  assert_predicate(Complex(2,3), :frozen?)
  assert_predicate(4+5i, :frozen?)
end
