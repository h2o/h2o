##
# Codegen tests

assert('peephole optimization does not eliminate move whose result is reused') do
  assert_raise LocalJumpError do
    def method
      yield
    end
    method(&a &&= 0)
  end
end

assert('empty condition in ternary expression parses correctly') do
  assert_equal(() ? 1 : 2, 2)
end

assert('method call with exactly 127 arguments') do
  def args_to_ary(*args)
    args
  end

  assert_equal [0]*127, args_to_ary(
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  )
end

assert('nested empty heredoc') do
  _, a = nil, <<B
#{<<A}
A
B
  assert_equal "\n", a
end

assert('splat in case splat') do
  a = *case
    when 0
      * = 1
  end

  assert_equal [1], a
end

assert('undef with 127 or more arguments') do
  assert_raise NameError do
    undef
      a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
      a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
      a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
      a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a
  end
end

assert('next in normal loop with 127 arguments') do
  assert_raise NameError do
    while true
      next A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A,A
    end
  end
end

assert('negate literal register alignment') do
  a = *case
  when 0
    -0.0
    2
  end

  assert_equal [2], a
end

assert('register window of calls (#3783)') do
  # NODE_FOR
  assert_nothing_raised do
    for i in []; end
  end

  # NODE_SYMBOLS
  assert_nothing_raised do
    %i(sym)
  end

  # NODE_SCALL
  assert_nothing_raised do
    Object.new&.__id__
  end

  # NODE_RESCUE with splat
  assert_nothing_raised do
    begin
      raise
    rescue *[Exception]
    end
  end

  # NODE_CASE
  assert_nothing_raised do
    case 1
    when nil
    end
  end

  # NODE_CASE with splat
  assert_nothing_raised do
    case 1
    when *nil
    end
  end

  # NODE_HASH
  assert_nothing_raised do
    {}.merge(
        0=>0,     1=>1,     2=>2,     3=>3,     4=>4,     5=>5,     6=>6,     7=>7,     8=>8,     9=>9,
       10=>10,   11=>11,   12=>12,   13=>13,   14=>14,   15=>15,   16=>16,   17=>17,   18=>18,   19=>19,
       20=>20,   21=>21,   22=>22,   23=>23,   24=>24,   25=>25,   26=>26,   27=>27,   28=>28,   29=>29,
       30=>30,   31=>31,   32=>32,   33=>33,   34=>34,   35=>35,   36=>36,   37=>37,   38=>38,   39=>39,
       40=>40,   41=>41,   42=>42,   43=>43,   44=>44,   45=>45,   46=>46,   47=>47,   48=>48,   49=>49,
       50=>50,   51=>51,   52=>52,   53=>53,   54=>54,   55=>55,   56=>56,   57=>57,   58=>58,   59=>59,
       60=>60,   61=>61,   62=>62,   63=>63,   64=>64,   65=>65,   66=>66,   67=>67,   68=>68,   69=>69,
       70=>70,   71=>71,   72=>72,   73=>73,   74=>74,   75=>75,   76=>76,   77=>77,   78=>78,   79=>79,
       80=>80,   81=>81,   82=>82,   83=>83,   84=>84,   85=>85,   86=>86,   87=>87,   88=>88,   89=>89,
       90=>90,   91=>91,   92=>92,   93=>93,   94=>94,   95=>95,   96=>96,   97=>97,   98=>98,   99=>99,
      100=>100, 101=>101, 102=>102, 103=>103, 104=>104, 105=>105, 106=>106, 107=>107, 108=>108, 109=>109,
      110=>110, 111=>111, 112=>112, 113=>113, 114=>114, 115=>115, 116=>116, 117=>117, 118=>118, 119=>119,
      120=>120, 121=>121, 122=>122, 123=>123, 124=>124, 125=>125, 126=>126)
  end

  # NODE_OP_ASGN
  o = Object.new
  class << o
    attr_accessor :a
  end

  o.a = 1
  assert_nothing_raised{ o.a += 1 }
  o.a = 1
  assert_nothing_raised{ o.a <<= 1 }
  o.a = 1
  assert_nothing_raised{ o.a &&= 1 }

  o = { k: 1 }
  assert_nothing_raised{ o[:k] += 1 }
  o = { k: 1 }
  assert_nothing_raised{ o[:k] <<= 1 }
  o = { k: 1 }
  assert_nothing_raised{ o[:k] &&= 1 }

  o = { k: 1 }
  assert_nothing_raised{ o[*[:k]] += 1 }
  o = { k: 1 }
  assert_nothing_raised{ o[*[:k]] <<= 1 }
  o = { k: 1 }
  assert_nothing_raised{ o[*[:k]] &&= 1 }

  # NODE_YIELD
  def check_node_yield
    yield
  end
  assert_nothing_raised do
    check_node_yield{}
  end

  # NODE_DXSTR
  assert_raise(NotImplementedError){ `#{:dynamic}` }

  # NODE_XSTR
  assert_raise(NotImplementedError){ `static` }

  # NODE_DREGX
  class Regexp; end
  assert_raise(NoMethodError){ /#{'dynamic'}tail/ }
  assert_raise(NoMethodError){ /#{'dynamic'}tail/iu }

  # NODE_REGX
  assert_raise(NoMethodError){ /static/ }
  assert_raise(NoMethodError){ /static/iu }
  Object.remove_const :Regexp

  # NODE_UNDEF
  assert_nothing_raised do
    class << Object.new
      undef send
    end
  end

  # NODE_ALIAS
  assert_nothing_raised do
    class << Object.new
      alias send2 send
    end
  end
end