assert('Kernel.eval', '15.3.1.2.3') do
  assert_equal(10) { Kernel.eval '1 * 10' }
  assert_equal('aaa') { Kernel.eval "'a' * 3" }
  assert_equal(10) {
    a = 10
    Kernel.eval "a"
  }
  assert_equal(20) {
    a = 10
    Kernel.eval "a = 20"
    a
  }
  assert_equal(15) {
    c = 5
    lambda {
      a = 10
      Kernel.eval "c = a + c"
    }.call
    c
  }
  assert_equal(5) {
    c = 5
    lambda {
      Kernel.eval 'lambda { c }.call'
    }.call
  }
  assert_equal(15) {
    c = 5
    lambda {
      a = 10
      Kernel.eval 'lambda { c = a + c }.call'
    }.call
    c
  }
  assert_equal(2) {
    a = 10
    Kernel.eval 'def f(a); b=a.send(:+, 1); end'
    f(1)
  }
end

assert('Kernel#eval', '15.3.1.3.12') do
  assert_equal(10) { eval '1 * 10' }
end

assert('rest arguments of eval') do
  assert_raise(ArgumentError) { Kernel.eval('0', 0, 'test', 0) }
  assert_equal ['test', 'test.rb', 10] do
    Kernel.eval('[\'test\', __FILE__, __LINE__]', nil, 'test.rb', 10)
  end
end

assert 'eval syntax error' do
  assert_raise(SyntaxError) do
    eval 'p "test'
  end
end

assert('String instance_eval') do
  obj = Object.new
  obj.instance_variable_set :@test, 'test'
  assert_raise(ArgumentError) { obj.instance_eval(0) { } }
  assert_raise(ArgumentError) { obj.instance_eval('0', 'test', 0, 'test') }
  assert_equal(['test.rb', 10]) { obj.instance_eval('[__FILE__, __LINE__]', 'test.rb', 10)}
  assert_equal('test') { obj.instance_eval('@test') }
  assert_equal('test') { obj.instance_eval { @test } }
end

assert('Kernel.#eval(string) context') do
  class TestEvalConstScope
    EVAL_CONST_CLASS = 'class'
    def const_string
      eval 'EVAL_CONST_CLASS'
    end
  end
  obj = TestEvalConstScope.new
  assert_raise(NameError) { eval 'EVAL_CONST_CLASS' }
  assert_equal('class') { obj.const_string }
end

