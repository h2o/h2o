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
# it's syntax error now
#  assert_raise LocalJumpError do
#    yield
#  end
  assert_raise LocalJumpError do
    o = Object.new
    def o.foo
      yield
    end
    o.foo
  end
end

assert('break', '11.5.2.4.3') do
  n = 0
  a = []
  while true
    n += 1
    a.push(n)
    if n > 3
      break
    end
  end

  assert_equal [1,2,3,4], a

  n = 0
  a = []
  6.times do
    n += 1
    a.push(n)
    if n > 3
      break
    end
  end
  assert_equal [1,2,3,4], a
end

assert('redo', '11.5.2.4.5') do
  sum = 0
  for i in 1..10
    sum += i
    i -= 1
    if i > 0
      redo
    end
  end

  assert_equal 220, sum

  n = 0
  a = []
  3.times do
    n += 1
    if n == 2
      redo
    end
    a.push(n)
  end
  assert_equal [1,3,4], a
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

assert('Abbreviated variable assignment of object attribute') do
  module Syntax4AbbrVarAsgnObjectAttr
    class A
      attr_accessor :c
      def b
        self.c ||= 1
      end
    end
  end
  assert_equal 1, Syntax4AbbrVarAsgnObjectAttr::A.new.b
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

assert('one-line pattern match') do
  1 => a
  assert_equal(1, a)
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
  module Kernel
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

    results = []
    assert_equal 'test sym test sym test', `test #{:sym} test #{:sym} test`

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
  result = class MethodDefinitionInCmdarg
    def self.bar(arg); arg end
    bar def foo; self.each do end end
  end
  assert_equal(:foo, result)
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

assert('local variable definition in default value and subsequent arguments') do
  def m(a = b = 1, c) [a, b, c] end
  assert_equal([1, 1, :c], m(:c))
  assert_equal([:a, nil, :c], m(:a, :c))

  def m(a = b = 1, &c) [a, b, c ? true : nil] end
  assert_equal([1, 1, nil], m)
  assert_equal([1, 1, true], m{})
  assert_equal([:a, nil, nil], m(:a))
  assert_equal([:a, nil, true], m(:a){})
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

assert 'keyword arguments' do
  def m(a, b:1) [a, b] end
  assert_equal [1, 1], m(1)
  assert_equal [1, 2], m(1, b: 2)

  def m(a, b:) [a, b] end
  assert_equal [1, 2], m(1, b: 2)
  assert_raise(ArgumentError) { m b: 1 }
  assert_raise(ArgumentError) { m 1 }

  def m(a:) a end
  assert_equal 1, m(a: 1)
  assert_raise(ArgumentError) { m }
  assert_raise(ArgumentError) { m 'a'  => 1, a: 1 }
  h = { a: 1 }
  assert_equal 1, m(**h)

  def m(a: 1) a end
  assert_equal 1, m
  assert_equal 2, m(a: 2)
  assert_raise(ArgumentError) { m 1 }

  def m(**) end
  assert_nil m
  assert_nil m a: 1, b: 2
  assert_raise(ArgumentError) { m 2 }

  def m(a, **) a end
  assert_equal 1, m(1)
  assert_equal 1, m(1, a: 2, b: 3)
  assert_raise(ArgumentError) { m('a' => 1, b: 2) }

  def m(a, **k) [a, k] end
  assert_equal [1, {}], m(1)
  assert_equal [1, {a: 2, b: 3}], m(1, a: 2, b: 3)
  assert_raise(ArgumentError) { m('a' => 1, b: 2) }

  def m(a=1, **) a end
  assert_equal 1, m
  assert_equal 2, m(2, a: 1, b: 0)

  def m(a=1, **k) [a, k] end
  assert_equal [1, {}], m
  assert_equal [1, {a: 1}], m(a: 1)
  assert_equal [2, {a: 1, b: 2}], m(2, a: 1, b: 2)
  assert_equal [{a: 1}, {b: 2}], m({a: 1}, b: 2)
  assert_raise(ArgumentError) { m({a: 1}, {b: 2}) }

  def m(*, a:) a end
  assert_equal 1, m(a: 1)
  assert_equal 3, m(1, 2, a: 3)
  assert_raise(ArgumentError) { m('a' => 1, a: 2) }

  def m(*a, b:) [a, b] end
  assert_equal [[], 1], m(b: 1)
  assert_equal [[1, 2], 3], m(1, 2, b: 3)
  assert_raise(ArgumentError) { m('a' => 1, b: 2) }

  def m(*a, b: 1) [a, b] end
  assert_equal [[], 1], m
  assert_equal [[1, 2, 3], 4], m(1, 2, 3, b: 4)
  assert_raise(ArgumentError) { m('a' => 1, b: 2) }

  def m(*, **) end
  assert_nil m()
  assert_nil m(a: 1, b: 2)
  assert_nil m(1, 2, 3, a: 4, b: 5)

  def m(*a, **) a end
  assert_equal [], m()
  assert_equal [1, 2, 3], m(1, 2, 3, a: 4, b: 5)
  assert_equal [1], m(1, **{a: 2})

  def m(*, **k) k end
  assert_equal({}, m())
  assert_equal({a: 4, b: 5}, m(1, 2, 3, a: 4, b: 5))

  def m(a = nil, b = nil, **k) [a, k] end
  assert_equal [nil, {}], m()
  assert_equal([nil, {a: 1}], m(a: 1))
  assert_equal([{"a" => 1}, {a: 1}], m({ "a" => 1 }, a: 1))
  assert_equal([{a: 1}, {}], m({a: 1}, {}))
  assert_equal([{}, {}], m({}))

  def m(*a, **k) [a, k] end
  assert_equal([[], {}], m())
  assert_equal([[1], {}], m(1))
  assert_equal([[], {a: 1, b: 2}], m(a: 1, b: 2))
  assert_equal([[1, 2, 3], {a: 2}], m(1, 2, 3, a: 2))
  assert_equal([[], {a: 1}], m(a: 1))
  assert_equal([[{"a" => 1}], {a: 1}], m({ "a" => 1 }, a: 1))
  assert_equal([[{a: 1}, {}], {}], m({a: 1}, {}))

  def m(a:, b:) [a, b] end
  assert_equal([1, 2], m(a: 1, b: 2))
  assert_raise(ArgumentError) { m("a" => 1, a: 1, b: 2) }

  def m(a:, b: 1) [a, b] end
  assert_equal([1, 1], m(a: 1))
  assert_equal([1, 2], m(a: 1, b: 2))
  assert_raise(ArgumentError) { m(b: 1) }
  assert_raise(ArgumentError) { m("a" => 1, a: 1, b: 2) }

  def m(a:, **) a end
  assert_equal(1, m(a: 1))
  assert_equal(1, m(a: 1, b: 2))

  def m(a:, **k) [a, k] end
  assert_equal([1, {}], m(a: 1))
  assert_equal([1, {b: 2, c: 3}], m(a: 1, b: 2, c: 3))

  def m(a:, &b) [a, b] end
  assert_equal([1, nil], m(a: 1))
  result = m(a: 1, &(l = ->{}))
  assert_equal([1, l], result)

  def m(a: 1, b:) [a, b] end
  assert_equal([1, 0], m(b: 0))
  assert_equal([3, 2], m(b: 2, a: 3))
  assert_raise(ArgumentError) { m a: 1 }

  def m(a: def m(a: 1) a end, b:)
    [a, b]
  end
  assert_equal([2, 3], m(a: 2, b: 3))
  assert_equal([:m, 1], m(b: 1))
  # Note the default value of a: in the original method.
  assert_equal(1, m())

  def m(a: 1, b: 2) [a, b] end
  assert_equal([1, 2], m())
  assert_equal([4, 3], m(b: 3, a: 4))

  def m(a: 1, **) a end
  assert_equal(1, m())
  assert_equal(2, m(a: 2, b: 1))

  def m(a: 1, **k) [a, k] end
  assert_equal([1, {b: 2, c: 3}], m(b: 2, c: 3))

  def m(a:, **) yield end
  assert_raise(ArgumentError) { m { :blk } }
  assert_equal :blk, m(a: 1){ :blk }

  def m(a:, **k, &b) [b.call, k] end
  assert_raise(ArgumentError) { m { :blk } }
  assert_equal [:blk, {b: 2}], m(a: 1, b: 2){ :blk }

  def m(**k, &b) [k, b] end
  assert_equal([{ a: 1, b: 2}, nil], m(a: 1, b: 2))
  assert_equal :blk, m{ :blk }[1].call

=begin
  def m(a, b=1, *c, (*d, (e)), f: 2, g:, h:, **k, &l)
    [a, b, c, d, e, f, g, h, k, l]
  end
  result = m(9, 8, 7, 6, f: 5, g: 4, h: 3, &(l = ->{}))
  assert_equal([9, 8, [7], [], 6, 5, 4, 3, {}, l], result)
  def m a, b=1, *c, d, e:, f: 2, g:, **k, &l
    [a, b, c, d, e, f, g, k, l]
  end
  result = m(1, 2, e: 3, g: 4, h: 5, i: 6, &(l = ->{}))
  assert_equal([1, 1, [], 2, 3, 2, 4, { h: 5, i: 6 }, l], result)
=end

  def m(a: b = 1, c:) [a, b, c] end
  assert_equal([1, 1, :c], m(c: :c))
  assert_equal([:a, nil, :c], m(a: :a, c: :c))
end

assert('numbered parameters') do
  assert_equal(15, [1,2,3,4,5].reduce {_1+_2})
  assert_equal(45, Proc.new do _1 + _2 + _3 + _4 + _5 + _6 + _7 + _8 + _9 end.call(*[1, 2, 3, 4, 5, 6, 7, 8, 9]))
end

assert('_0 is not numbered parameter') do
  _0 = :l
  assert_equal(:l, ->{_0}.call)
end

assert('argument forwarding') do
  c = Class.new {
    def a0(*a,&b)
      assert_equal([1,2,3], a)
      assert_not_nil(b)
    end
    def a(...)
      a0(...)
    end
    def b(a,...)
      assert_equal(a,1)
      a0(1,...)
    end
    def c ...
      a(...)
    end
    def d a,...
      assert_equal(a,1)
      b(1,...)
    end
  }
  o = c.new
  o.a(1,2,3){}
  o.b(1,2,3){}
  o.c(1,2,3){}
  o.d(1,2,3){}
end

assert('endless def') do
  c = Class.new {
    def m1 = 42
    def m2() = 42
    def m3(x) = x+1
    def self.s1 = 42
    def self.s2() = 42
    def self.s3(x) = x + 1
    def cm1 = m3 42
    def cm2() = m3 42
    def cm3(x) = m3 x+1
    def self.cs1 = s3 42
    def self.cs2() = s3 42
    def self.cs3(x) = s3 x + 1
  }
  o = c.new
  assert_equal(42, o.m1)
  assert_equal(43, o.m3(o.m2))
  assert_equal(42, c.s1)
  assert_equal(43, c.s3(c.s2))
  assert_equal(43, o.cm1)
  assert_equal(45, o.cm3(o.cm2))
  assert_equal(43, c.cs1)
  assert_equal(45, c.cs3(c.cs2))
end
