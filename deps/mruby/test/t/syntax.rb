assert('__FILE__') do
  file = __FILE__[-9, 9]
  assert_equal 'syntax.rb', file
end

assert('__LINE__') do
  assert_equal 7, __LINE__
end

assert('super', '11.3.4') do
  assert_raise NoMethodError do
    super
  end

  class SuperFoo
    def foo
      true
    end
    def bar(*a)
      a
    end
  end
  class SuperBar < SuperFoo
    def foo
      super
    end
    def bar(*a)
      super(*a)
    end
  end
  bar = SuperBar.new

  assert_true bar.foo
  assert_equal [1,2,3], bar.bar(1,2,3)
end

assert('yield', '11.3.5') do
  assert_raise LocalJumpError do
    yield
  end
  assert_raise LocalJumpError do
    o = Object.new
    def o.foo
      yield
    end
    o.foo
  end
end

assert('redo in a for loop (#3275)') do
  sum = 0
  for i in 1..10
    sum += i
    i -= 1
    if i > 0
      redo
    end
  end

  assert_equal 220, sum
end

assert('Abbreviated variable assignment', '11.4.2.3.2') do
  a ||= 1
  b &&= 1
  c = 1
  c += 2

  assert_equal 1, a
  assert_nil b
  assert_equal 3, c
end

assert('case expression', '11.5.2.2.4') do
  # case-expression-with-expression, one when-clause
  x = 0
  case "a"
  when "a"
    x = 1
  end
  assert_equal 1, x

  # case-expression-with-expression, multiple when-clauses
  x = 0
  case "b"
  when "a"
    x = 1
  when "b"
    x = 2
  end
  assert_equal 2, x

  # no matching when-clause
  x = 0
  case "c"
  when "a"
    x = 1
  when "b"
    x = 2
  end
  assert_equal 0, x

  # case-expression-with-expression, one when-clause and one else-clause
  a = 0
  case "c"
  when "a"
    x = 1
  else
    x = 3
  end
  assert_equal 3, x

  # case-expression-without-expression, one when-clause
  x = 0
  case
  when true
    x = 1
  end
  assert_equal 1, x

  # case-expression-without-expression, multiple when-clauses
  x = 0
  case
  when 0 == 1
    x = 1
  when 1 == 1
    x = 2
  end
  assert_equal 2, x

  # case-expression-without-expression, one when-clause and one else-clause
  x = 0
  case
  when 0 == 1
    x = 1
  else
    x = 3
  end
  assert_equal 3, x

  # multiple when-arguments
  x = 0
  case 4
  when 1, 3, 5
    x = 1
  when 2, 4, 6
    x = 2
  end
  assert_equal 2, x

  # when-argument with splatting argument
  x = :integer
  odds  = [ 1, 3, 5, 7, 9 ]
  evens = [ 2, 4, 6, 8 ]
  case 5
  when *odds
    x = :odd
  when *evens
    x = :even
  end
  assert_equal :odd, x

  true
end

assert('Nested const reference') do
  module Syntax4Const
    CONST1 = "hello world"
    class Const2
      def const1
        CONST1
      end
    end
  end
  assert_equal "hello world", Syntax4Const::CONST1
  assert_equal "hello world", Syntax4Const::Const2.new.const1
end

assert('Abbreviated variable assignment as returns') do
  module Syntax4AbbrVarAsgnAsReturns
    class A
      def b
        @c ||= 1
      end
    end
  end
  assert_equal 1, Syntax4AbbrVarAsgnAsReturns::A.new.b
end

assert('Splat and multiple assignment') do
  *a = *[1,2,3]
  b, *c = *[7,8,9]

  assert_equal [1,2,3], a
  assert_equal 7, b
  assert_equal [8,9], c

  (a, b), c = [1,2],3
  assert_equal [1,2,3], [a,b,c]
  (a, b), c = 1,2,3
  assert_equal [1,nil,2], [a,b,c]
end

assert('Splat and multiple assignment from variable') do
  a = [1, 2, 3]
  b, *c = a

  assert_equal 1, b
  assert_equal [2, 3], c
end

assert('Splat and multiple assignment from variables') do
  a = [1, 2, 3]
  b = [4, 5, 6, 7]
  c, d, *e, f, g = *a, *b

  assert_equal 1, c
  assert_equal 2, d
  assert_equal [3, 4, 5], e
  assert_equal 6, f
  assert_equal 7, g
end

assert('Splat and multiple assignment in for') do
  a = [1, 2, 3, 4, 5, 6, 7]
  for b, c, *d, e, f in [a] do
  end

  assert_equal 1, b
  assert_equal 2, c
  assert_equal [3, 4, 5], d
  assert_equal 6, e
  assert_equal 7, f
end

assert('Splat without assignment') do
  * = [0]
  a, * = [1, 2]
  assert_equal 1, a
end

assert('multiple assignment (rest)') do
  *a = 0
  assert_equal [0], a
end

assert('multiple assignment (rest+post)') do
  *a, b = 0, 1, 2
  *c, d = 3

  assert_equal [0, 1], a
  assert_equal 2, b
  assert_equal [], c
  assert_equal 3, d
end

assert('multiple assignment (nosplat array rhs)') do
  a, *b = []
  *c, d = [0]
  e, *f, g = [1, 2]

  assert_nil a
  assert_equal [], b
  assert_equal [], c
  assert_equal 0, d
  assert_equal 1, e
  assert_equal [], f
  assert_equal 2, g
end

assert('multiple assignment (empty array rhs #3236, #3239)') do
  a,b,*c = []; assert_equal [nil, nil, []], [a, b, c]
  a,b,*c = [1]; assert_equal [1, nil, []], [a, b, c]
  a,b,*c = [nil]; assert_equal [nil,nil, []], [a, b, c]
  a,b,*c = [[]]; assert_equal [[], nil, []], [a, b, c]
end

assert('Return values of case statements') do
  a = [] << case 1
  when 3 then 2
  when 2 then 2
  when 1 then 2
  end

  b = [] << case 1
  when 2 then 2
  else
  end

  def fb
    n = 0
    Proc.new do
      n += 1
      case
      when n % 15 == 0
      else n
      end
    end
  end

  assert_equal [2], a
  assert_equal [nil], b
  assert_equal 1, fb.call
end

assert('Return values of if and case statements') do
  true_clause_value =
    if true
      1
    else
      case 2
      when 3
      end
      4
    end

  assert_equal 1, true_clause_value
end

assert('Return values of no expression case statement') do
  when_value =
    case
    when true
      1
    end

  assert_equal 1, when_value
end

assert('splat object in assignment') do
  o = Object.new
  def o.to_a
    nil
  end
  assert_equal [o], (a = *o)

  def o.to_a
    1
  end
  assert_raise(TypeError) { a = *o }

  def o.to_a
    [2]
  end
  assert_equal [2], (a = *o)
end

assert('splat object in case statement') do
  o = Object.new
  def o.to_a
    nil
  end
  a = case o
  when *o
    1
  end
  assert_equal 1, a
end

assert('splat in case statement') do
  values = [3,5,1,7,8]
  testa = [1,2,7]
  testb = [5,6]
  resulta = []
  resultb = []
  resultc = []
  values.each do |value|
    case value
    when *testa
      resulta << value
    when *testb
      resultb << value
    else
      resultc << value
    end
  end

  assert_equal [1,7], resulta
  assert_equal [5], resultb
  assert_equal [3,8], resultc
end

assert('External command execution.') do
  class << Kernel
    sym = '`'.to_sym
    alias_method :old_cmd, sym

    results = []
    define_method(sym) do |str|
      results.push str
      str
    end

    `test` # NOVAL NODE_XSTR
    `test dynamic #{sym}` # NOVAL NODE_DXSTR
    assert_equal ['test', 'test dynamic `'], results

    t = `test` # VAL NODE_XSTR
    assert_equal 'test', t
    assert_equal ['test', 'test dynamic `', 'test'], results

    t = `test dynamic #{sym}` # VAL NODE_DXSTR
    assert_equal 'test dynamic `', t
    assert_equal ['test', 'test dynamic `', 'test', 'test dynamic `'], results

    alias_method sym, :old_cmd
  end
  true
end

assert('parenthesed do-block in cmdarg') do
  class ParenDoBlockCmdArg
    def test(block)
      block.call
    end
  end
  x = ParenDoBlockCmdArg.new
  result = x.test (Proc.new do :ok; end)
  assert_equal :ok, result
end

assert('method definition in cmdarg') do
  if false
    bar def foo; self.each do end end
  end
  true
end

assert('optional argument in the rhs default expressions') do
  class OptArgInRHS
    def foo
      "method called"
    end
    def t(foo = foo)
      foo
    end
    def t2(foo = foo())
      foo
    end
  end
  o = OptArgInRHS.new
  assert_nil(o.t)
  assert_equal("method called", o.t2)
end

assert('optional block argument in the rhs default expressions') do
  assert_nil(Proc.new {|foo = foo| foo}.call)
end

assert('multiline comments work correctly') do
=begin
this is a comment with nothing after begin and end
=end
=begin  this is a comment 
this is a comment with extra after =begin
=end
=begin
this is a comment that has =end with spaces after it
=end  
=begin this is a comment
this is a comment that has extra after =begin and =end with spaces after it
=end  
  line = __LINE__
=begin	this is a comment
this is a comment that has extra after =begin and =end with tabs after it
=end	xxxxxxxxxxxxxxxxxxxxxxxxxx
  assert_equal(line + 4, __LINE__)
end
