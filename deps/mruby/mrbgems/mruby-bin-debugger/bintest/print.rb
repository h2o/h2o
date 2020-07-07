require 'open3'
require 'tempfile'
require 'strscan'

class BinTest_MrubyBinDebugger
#  @debug1=false
#  @debug2=true
  def self.test(rubysource, testcase)
    script, bin = Tempfile.new(['test', '.rb']), Tempfile.new(['test', '.mrb'])

    # .rb
    script.write rubysource
    script.flush

    # compile
    `./bin/mrbc -g -o "#{bin.path}" "#{script.path}"`

    # add mrdb quit
    testcase << {:cmd=>"quit"}

    stdin_data = testcase.map{|t| t[:cmd]}.join("\n") << "\n"

    prompt = /^\(#{Regexp.escape(script.path)}:\d+\) /
    ["bin/mrdb #{script.path}","bin/mrdb -b #{bin.path}"].each do |cmd|
      o, s = Open3.capture2(cmd, :stdin_data => stdin_data)
      scanner = StringScanner.new(o)
      scanner.skip_until(prompt)
      testcase.each do |tc|
        exp = tc[:exp]
        if exp
          act = scanner.scan_until(/\n/)
          break unless assert_operator act, :start_with?, exp
        end
        scanner.skip_until(prompt)
      end

=begin
if @debug1
  o.split("\n").each_with_index do |i,actual|
    p [i,actual]
  end
end
      # compare actual / expected
      o.split("\n").each do |actual|
        next if actual.empty?
        exp = exp_vals.shift
if @debug2
  a = true
  a = actual.include?(exp) unless exp.nil?
  p [actual, exp] unless a
end
        assert_true actual.include?(exp) unless exp.nil?
      end
=end
    end
  end
end

assert('mruby-bin-debugger(print) invalid arguments') do
  # ruby source
  src =  "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"p",   :exp=>"Parameter not specified."}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) nomal') do
  # ruby source
  src = <<"SRC"
foo = 'foo'
bar = foo
baz = bar
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"p (1+2)",   :exp=>'$1 = 3'}
  tc << {:cmd=>"p foo",     :exp=>'$2 = "foo"'}
  tc << {:cmd=>"p foo*=2",  :exp=>'$3 = "foofoo"'}
  tc << {:cmd=>"s"}
  tc << {:cmd=>"p bar",     :exp=>'$4 = "foofoo"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) error') do
  # ruby source
  src =  "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"p (1+2",  :exp=>'$1 = line 1: syntax error'}
  tc << {:cmd=>"p bar",   :exp=>'$2 = undefined method'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

# Kernel#instance_eval(string) does't work multiple statements.
=begin
assert('mruby-bin-debugger(print) multiple statements') do
  # ruby source
  src = <<"SRC"
x = 0
y = 0
z = 0
SRC

  # test case
  tc = []
  tc << {:cmd=>"s",}
  tc << {:cmd=>"p x=1;x+=2",  :exp=>"3"}
  tc << {:cmd=>"s",}
  tc << {:cmd=>"p x",         :exp=>"3"}

  BinTest_MrubyBinDebugger.test(src, tc)
end
=end

assert('mruby-bin-debugger(print) scope:top') do
  # ruby source (bp is break point)
  src = "bp=nil\n"

  # test case
  tc = []
  tc << {:cmd=>"p self",  :exp=>'$1 = main'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) scope:class') do
  # ruby source (bp is break point)
  src = <<"SRC"
class TestClassScope
  bp = nil
end
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"p self",  :exp=>'$1 = TestClassScope'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) scope:module') do
  # ruby source (bp is break point)
  src = <<"SRC"
class TestModuleScope
  bp = nil
end
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"p self",  :exp=>'$1 = TestModuleScope'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) scope:instance method') do
  # ruby source (bp is break point)
  src = <<"SRC"
class TestMethodScope
  def m
    bp = nil
  end
end
TestMethodScope.new.m
SRC

  tc = []
  tc << {:cmd=>"b 3"}
  tc << {:cmd=>"r"}
  tc << {:cmd=>"p self",  :exp=>'$1 = #<TestMethodScope:'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) scope:class method') do
  # ruby source (bp is break point)
  src = <<"SRC"
class TestClassMethodScope
  def self.cm
    bp = nil
  end
end
TestClassMethodScope.cm
SRC

  tc = []
  tc << {:cmd=>"b 3"}
  tc << {:cmd=>"r"}
  tc << {:cmd=>"p self",  :exp=>'$1 = TestClassMethodScope'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) scope:block') do
  # ruby source (bp is break point)
  src = <<"SRC"
1.times do
  bp = nil
end
class TestBlockScope
  1.times do
    bp = nil
  end
  def m
    1.times do
      bp = nil
    end
  end
end
TestBlockScope.new.m
SRC

  tc = []
  tc << {:cmd=>"b 2"}
  tc << {:cmd=>"b 6"}
  tc << {:cmd=>"b 10"}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p self", :exp=>'$1 = main'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p self", :exp=>'$2 = TestBlockScope'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p self", :exp=>'$3 = #<TestBlockScope:'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) same name:local variabe') do
  # ruby source (bp is break point)
  src = <<"SRC"
lv = 'top'
class TestLocalVariableName
  lv = 'class'
  def m
    lv = 'instance method'
    bp = nil
  end
  bp = nil
end
TestLocalVariableName.new.m
bp = nil
SRC

  tc = []
  tc << {:cmd=>"b 6"}
  tc << {:cmd=>"b 8"}
  tc << {:cmd=>"b 11"}
  tc << {:cmd=>"r"}
  tc << {:cmd=>"p lv", :exp=>'$1 = "class"'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p lv", :exp=>'$2 = "instance method"'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p lv", :exp=>'$3 = "top"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) same name:instance variabe') do
  # ruby source (bp is break point)
  src = <<"SRC"
@iv = 'top'
class TestInstanceVariableName
  def initialize(v)
    @iv = v
  end
  def m
    bp = nil
  end
end
i1 = TestInstanceVariableName.new('instance1')
i2 = TestInstanceVariableName.new('instance2')
i1.m
i2.m
bp = nil
SRC

  tc = []
  tc << {:cmd=>"b 7"}
  tc << {:cmd=>"b 14"}
  tc << {:cmd=>"r"}
  tc << {:cmd=>"p @iv", :exp=>'$1 = "instance1"'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p @iv", :exp=>'$2 = "instance2"'}
  tc << {:cmd=>"c"}
  tc << {:cmd=>"p @iv", :exp=>'$3 = "top"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

# Kernel#instance_eval(string) does't work const.
=begin
assert('mruby-bin-debugger(print) same name:const') do
  # ruby source (bp is break point)
  src = <<"SRC"
CONST='top'
class TestConstNameSuperClass
  CONST='super class'
  def m
    bp = nil
  end
end
class TestConstNameSubClass < TestConstNameSuperClass
  CONST='sub class'
  def m
    bp = nil
  end
end

TestConstNameSuperClass.new.m()
TestConstNameSubClass.new.m()
bp = nil
SRC

  # todo: wait for 'break' to be implemented
  tc = []
  9.times { tc << {:cmd=>"s"} }
  tc << {:cmd=>"p CONST", :exp=>"super class"}
  3.times { tc << {:cmd=>"s"} }
  tc << {:cmd=>"p CONST", :exp=>"sub class"}
  1.times { tc << {:cmd=>"s"} }
  tc << {:cmd=>"p CONST", :exp=>"top"}

  BinTest_MrubyBinDebugger.test(src, tc)
end
=end

assert('mruby-bin-debugger(print) Literal:Numeric') do
  # ruby source
  src =  "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"p 100",     :exp=>'$1 = 100'}
  tc << {:cmd=>"p -0b100",  :exp=>'$2 = -4'}
  tc << {:cmd=>"p +0100",   :exp=>'$3 = 64'}
  tc << {:cmd=>"p 0x100",   :exp=>'$4 = 256'}
  tc << {:cmd=>"p 1_234",   :exp=>'$5 = 1234'}
  tc << {:cmd=>"p 0b1000_0000", :exp=>"$6 = #{0b1000_0000}"}
  tc << {:cmd=>"p 0x1000_0000", :exp=>"$7 = #{0x1000_0000}"}

  tc << {:cmd=>"p 3.14",    :exp=>'$8 = 3.14'}
  tc << {:cmd=>"p -12.3",   :exp=>'$9 = -12.3'}
  tc << {:cmd=>"p +12.000", :exp=>'$10 = 12'}
  tc << {:cmd=>"p 1e4",     :exp=>'$11 = 10000'}
  tc << {:cmd=>"p -0.1e-2", :exp=>'$12 = -0.001'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Literal:String') do
  # ruby source
  src = <<"SRC"
foo = 'foo'
bar = "bar"
baz = "baz"
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"s"}

  tc << {:cmd=>'p "str"',        :exp=>'$1 = "str"'}
  tc << {:cmd=>'p "s\tt\rr\n"',  :exp=>'$2 = "s\\tt\\rr\\n"'}
  tc << {:cmd=>'p "\C-a\C-z"',   :exp=>'$3 = "\\x01\\x1a"'}
  tc << {:cmd=>'p "#{foo+bar}"', :exp=>'$4 = "foobar"'}

  tc << {:cmd=>'p \'str\'',          :exp=>'$5 = "str"'}
  tc << {:cmd=>'p \'s\\tt\\rr\\n\'', :exp=>'$6 = "s\\\\tt\\\\rr\\\\n"'}
  tc << {:cmd=>'p \'\\C-a\\C-z\'',   :exp=>'$7 = "\\\\C-a\\\\C-z"'}
  tc << {:cmd=>'p \'#{foo+bar}\'',   :exp=>'$8 = "\\#{foo+bar}"'}

  tc << {:cmd=>'p %!str!',        :exp=>'$9 = "str"'}
  tc << {:cmd=>'p %!s\tt\rr\n!',  :exp=>'$10 = "s\\tt\\rr\\n"'}
  tc << {:cmd=>'p %!\C-a\C-z!',   :exp=>'$11 = "\\x01\\x1a"'}
  tc << {:cmd=>'p %!#{foo+bar}!', :exp=>'$12 = "foobar"'}

  tc << {:cmd=>'p %Q!str!',        :exp=>'$13 = "str"'}
  tc << {:cmd=>'p %Q!s\tt\rr\n!',  :exp=>'$14 = "s\\tt\\rr\\n"'}
  tc << {:cmd=>'p %Q!\C-a\C-z!',   :exp=>'$15 = "\\x01\\x1a"'}
  tc << {:cmd=>'p %Q!#{foo+bar}!', :exp=>'$16 = "foobar"'}

  tc << {:cmd=>'p %q!str!',          :exp=>'$17 = "str"'}
  tc << {:cmd=>'p %q!s\\tt\\rr\\n!', :exp=>'$18 = "s\\\\tt\\\\rr\\\\n"'}
  tc << {:cmd=>'p %q!\\C-a\\C-z!',   :exp=>'$19 = "\\\\C-a\\\\C-z"'}
  tc << {:cmd=>'p %q!#{foo+bar}!',   :exp=>'$20 = "\\#{foo+bar}"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Literal:Array') do
  # ruby source
  src = <<"SRC"
foo = 'foo'
bar = "bar"
baz = "baz"
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"s"}

  tc << {:cmd=>'p []',                      :exp=>'$1 = []'}
  tc << {:cmd=>'p [ 5,  12,   8,    10, ]', :exp=>'$2 = [5, 12, 8, 10]'}
  tc << {:cmd=>'p [1,2.5,"#{foo+bar}"]',    :exp=>'$3 = [1, 2.5, "foobar"]'}
  tc << {:cmd=>'p %w[3.14 A\ &\ B #{foo}]', :exp=>'$4 = ["3.14", "A & B", "\#{foo}"]'}
  tc << {:cmd=>'p %W[3.14 A\ &\ B #{foo}]', :exp=>'$5 = ["3.14", "A & B", "foo"]'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Literal:Hash') do
  # ruby source
  src = <<"SRC"
foo = 'foo'
bar = "bar"
baz = "baz"
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"s"}

  tc << {:cmd=>'p {}',                              :exp=>'$1 = {}'}
  tc << {:cmd=>'p {"one"=>1,"two"=>2}',             :exp=>'$2 = {"one"=>1, "two"=>2}'}
  tc << {:cmd=>'p {:eins=>"1",   :zwei=>"2", }',    :exp=>'$3 = {:eins=>"1", :zwei=>"2"}'}
  tc << {:cmd=>'p {uno:"one", dos: 2}',             :exp=>'$4 = {:uno=>"one", :dos=>2}'}
  tc << {:cmd=>'p {"one"=>1, :zwei=>2, tres:3}',    :exp=>'$5 = {"one"=>1, :zwei=>2, :tres=>3}'}
  tc << {:cmd=>'p {:foo=>"#{foo}",:bar=>"#{bar}"}', :exp=>'$6 = {:foo=>"foo", :bar=>"bar"}'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Literal:Range') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>'p 1..10',    :exp=>'$1 = 1..10'}
  tc << {:cmd=>'p 1...10',   :exp=>'$2 = 1...10'}
  tc << {:cmd=>'p 100..10',  :exp=>'$3 = 100..10'}
  tc << {:cmd=>'p 1 ... 10', :exp=>'$4 = 1...10'}

  tc << {:cmd=>'p "1" .. "9"',  :exp=>'$5 = "1".."9"'}
  tc << {:cmd=>'p "A" ... "Z"', :exp=>'$6 = "A"..."Z"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Literal:Symbol') do
  # ruby source
  src = <<"SRC"
foo = 'foo'
bar = "bar"
baz = "baz"
SRC

  # test case
  tc = []
  tc << {:cmd=>"s"}
  tc << {:cmd=>"s"}

  tc << {:cmd=>'p :sym',          :exp=>'$1 = :sym'}
  tc << {:cmd=>'p :"sd"',         :exp=>'$2 = :sd'}
  tc << {:cmd=>"p :'ss'",         :exp=>'$3 = :ss'}
  tc << {:cmd=>'p :"123"',        :exp=>'$4 = :"123"'}
  tc << {:cmd=>'p :"#{foo} baz"', :exp=>'$5 = :"foo baz"'}
  tc << {:cmd=>'p %s!symsym!',    :exp=>'$6 = :symsym'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Unary operation') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>'p +10',    :exp=>'$1 = 10'}
  tc << {:cmd=>'p -100',   :exp=>'$2 = -100'}
  tc << {:cmd=>'p !true',  :exp=>'$3 = false'}
  tc << {:cmd=>'p !false', :exp=>'$4 = true'}
  tc << {:cmd=>'p !nil',   :exp=>'$5 = true'}
  tc << {:cmd=>'p !1',     :exp=>'$6 = false'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Binary operation') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, 8
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p a+1',   :exp=>'$1 = 2'}
  tc << {:cmd=>'p 2-b',   :exp=>'$2 = -3'}
  tc << {:cmd=>'p c * 3', :exp=>'$3 = 24'}
  tc << {:cmd=>'p a/b',   :exp=>'$4 = 0.2'}
  tc << {:cmd=>'p c%b',   :exp=>'$5 = 3'}
  tc << {:cmd=>'p 2**10', :exp=>'$6 = 1024'}
  tc << {:cmd=>'p ~3',    :exp=>'$7 = -4'}

  tc << {:cmd=>'p 1<<2',  :exp=>'$8 = 4'}
  tc << {:cmd=>'p 64>>5', :exp=>'$9 = 2'}

  tc << {:cmd=>'p a|c',   :exp=>'$10 = 9'}
  tc << {:cmd=>'p a&b',   :exp=>'$11 = 1'}
  tc << {:cmd=>'p a^b',   :exp=>'$12 = 4'}

  tc << {:cmd=>'p a>b',   :exp=>'$13 = false'}
  tc << {:cmd=>'p a<b',   :exp=>'$14 = true'}
  tc << {:cmd=>'p b>=5',  :exp=>'$15 = true'}
  tc << {:cmd=>'p b<=5',  :exp=>'$16 = true'}

  tc << {:cmd=>'p "A"<=>"B"', :exp=>'$17 = -1'}
  tc << {:cmd=>'p "A"=="B"',  :exp=>'$18 = false'}
  tc << {:cmd=>'p "A"==="B"', :exp=>'$19 = false'}
  tc << {:cmd=>'p "A"!="B"',  :exp=>'$20 = true'}

  tc << {:cmd=>'p false || true', :exp=>'$21 = true'}
  tc << {:cmd=>'p false && true', :exp=>'$22 = false'}

  tc << {:cmd=>'p not nil',        :exp=>'$23 = true'}
  tc << {:cmd=>'p false or true',  :exp=>'$24 = true'}
  tc << {:cmd=>'p false and true', :exp=>'$25 = false'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Ternary operation') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, -10
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p (a < b) ? a : b',          :exp=>'$1 = 1'}
  tc << {:cmd=>'p (a > b) ? a : b',          :exp=>'$2 = 5'}
  tc << {:cmd=>'p true ? "true" : "false"',  :exp=>'$3 = "true"'}
  tc << {:cmd=>'p false ? "true" : "false"', :exp=>'$4 = "false"'}
  tc << {:cmd=>'p nil ? "true" : "false"',   :exp=>'$5 = "false"'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Substitution:simple') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, -10
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p a=2',               :exp=>'$1 = 2'}
  tc << {:cmd=>'p foo=[foo,bar,baz]', :exp=>'$2 = ["foo", "bar", "baz"]'}

  tc << {:cmd=>'p undefined=-1',      :exp=>'$3 = -1'}
  tc << {:cmd=>'p "#{undefined}"',    :exp=>'$4 = undefined method'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Substitution:self') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, -10
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p a+=9',   :exp=>'$1 = 10'}
  tc << {:cmd=>'p b-=c',   :exp=>'$2 = 15'}
  tc << {:cmd=>'p bar*=2', :exp=>'$3 = "barbar"'}
  tc << {:cmd=>'p a/=4',   :exp=>'$4 = 2.5'}
  tc << {:cmd=>'p c%=4',   :exp=>'$5 = 2'}

  tc << {:cmd=>'p b&=0b0101', :exp=>'$6 = 5'}
  tc << {:cmd=>'p c|=0x10',   :exp=>'$7 = 18'}

  tc << {:cmd=>'p "#{a} #{b} #{c}"',     :exp=>'$8 = "2.5 5 18"'}
  tc << {:cmd=>'p "#{foo}#{bar}#{baz}"', :exp=>'$9 = "foobarbarbaz"'}

  tc << {:cmd=>'p a,b,c=[10,20,30]',:exp=>'$10 = [10, 20, 30]'}
  tc << {:cmd=>'p [a,b,c]',         :exp=>'$11 = [10, 20, 30]'}
  tc << {:cmd=>'p a,b=b,a',         :exp=>'$12 = [20, 10]'}
  tc << {:cmd=>'p [a,b]',           :exp=>'$13 = [20, 10]'}

  tc << {:cmd=>'p undefined=-1',    :exp=>'$14 = -1'}
  tc << {:cmd=>'p "#{undefined}"',  :exp=>'$15 = undefined method'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Substitution:multiple') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, -10
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p a,b=[10,20]',   :exp=>'$1 = [10, 20]'}
  tc << {:cmd=>'p [a,b,c]',       :exp=>'$2 = [10, 20, -10]'}

  tc << {:cmd=>'p foo,bar=["FOO","BAR","BAZ"]', :exp=>'$3 = ["FOO", "BAR", "BAZ"]'}
  tc << {:cmd=>'p [foo,bar,baz]', :exp=>'$4 = ["FOO", "BAR", "baz"]'}

  tc << {:cmd=>'p a,foo=foo,a',   :exp=>'$5 = ["FOO", 10]'}
  tc << {:cmd=>'p [a,foo]',       :exp=>'$6 = ["FOO", 10]'}

#  tc << {:cmd=>'p a,*b=[123, 456, 789]'}
#  tc << {:cmd=>'p [a,b]',       :exp=>'[123, [456, 789]]'}

  BinTest_MrubyBinDebugger.test(src, tc)
end

assert('mruby-bin-debugger(print) Substitution:self') do
  # ruby source
  src = <<"SRC"
CONST = 100
a,b,c = 1, 5, -10
foo,bar,baz = 'foo','bar','baz'
ary = []
SRC

  # test case
  tc = []
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}
  tc << {:cmd=>'s'}

  tc << {:cmd=>'p a+=9',   :exp=>'$1 = 10'}
  tc << {:cmd=>'p b-=c',   :exp=>'$2 = 15'}
  tc << {:cmd=>'p bar*=2', :exp=>'$3 = "barbar"'}
  tc << {:cmd=>'p a/=4',   :exp=>'$4 = 2.5'}
  tc << {:cmd=>'p c%=4',   :exp=>'$5 = 2'}

  tc << {:cmd=>'p b&=0b0101', :exp=>'$6 = 5'}
  tc << {:cmd=>'p c|=0x10',   :exp=>'$7 = 18'}

  tc << {:cmd=>'p "#{a} #{b} #{c}"',     :exp=>'$8 = "2.5 5 18"'}
  tc << {:cmd=>'p "#{foo}#{bar}#{baz}"', :exp=>'$9 = "foobarbarbaz"'}

  tc << {:cmd=>'p a,b,c=[10,20,30]',:exp=>'$10 = [10, 20, 30]'}
  tc << {:cmd=>'p [a,b,c]',         :exp=>'$11 = [10, 20, 30]'}
  tc << {:cmd=>'p a,b=b,a',         :exp=>'$12 = [20, 10]'}
  tc << {:cmd=>'p [a,b]',           :exp=>'$13 = [20, 10]'}

  tc << {:cmd=>'p undefined=-1',    :exp=>'$14 = -1'}
  tc << {:cmd=>'p "#{undefined}"',  :exp=>'$15 = undefined method'}

  BinTest_MrubyBinDebugger.test(src, tc)
end
