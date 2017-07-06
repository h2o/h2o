require 'open3'
require 'tempfile'

class BinTest_MrubyBinDebugger
  @debug1=false
  @debug2=true
  @debug3=true
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

    ["bin/mrdb #{script.path}","bin/mrdb -b #{bin.path}"].each do |cmd|
      o, s = Open3.capture2(cmd, :stdin_data => stdin_data)

      exp_vals = testcase.map{|t| t.fetch(:exp, nil)}
      unexp_vals = testcase.map{|t| t.fetch(:unexp, nil)}

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
      # compare actual / unexpected
      o.split("\n").each do |actual|
        next if actual.empty?
        unexp = unexp_vals.shift
if @debug3
  a = false
  a = actual.include?(unexp) unless unexp.nil?
  p [actual, unexp] if a
end
        assert_false actual.include?(unexp) unless unexp.nil?
      end
    end
  end
end

INVCMD = "invalid command"

assert('mruby-bin-debugger(mrdb) command line') do
  # ruby source
  src = "foo = 'foo'\n"

  str = ""
  103.times {
    str += "1234567890"
  }
  cmd = "p a=#{str}"

  # test case
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>cmd[0...1023], :unexp=>'command line too long.'}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>cmd[0...1024], :unexp=>'command line too long.'}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>cmd[0...1025], :exp=>'command line too long.'}])
end

assert('mruby-bin-debugger(mrdb) command: "break"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"b",     :unexp=>INVCMD}
  tc << {:cmd=>"br",    :unexp=>INVCMD}
  tc << {:cmd=>"brea",  :unexp=>INVCMD}
  tc << {:cmd=>"break", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"bl",     :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"breaka", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "continue"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"c",         :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"co",        :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"continu",   :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"continue",  :unexp=>INVCMD}])

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"cn",        :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"continuee", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "delete"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"d 1",      :unexp=>INVCMD}
  tc << {:cmd=>"de 1",     :unexp=>INVCMD}
  tc << {:cmd=>"delet 1",  :unexp=>INVCMD}
  tc << {:cmd=>"delete 1", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"dd 1",      :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"deletee 1", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "disable"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"dis",     :unexp=>INVCMD}
  tc << {:cmd=>"disa",    :unexp=>INVCMD}
  tc << {:cmd=>"disabl",  :unexp=>INVCMD}
  tc << {:cmd=>"disable", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"di",       :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"disb",     :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"disablee", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "enable"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"en",     :unexp=>INVCMD}
  tc << {:cmd=>"ena",    :unexp=>INVCMD}
  tc << {:cmd=>"enabl",  :unexp=>INVCMD}
  tc << {:cmd=>"enable", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"e",       :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"enb",     :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"enablee", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "eval"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"ev",   :unexp=>INVCMD}
  tc << {:cmd=>"eva",  :unexp=>INVCMD}
  tc << {:cmd=>"eval", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"e",     :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"evl",   :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"evall", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "help"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"h",    :unexp=>INVCMD}
  tc << {:cmd=>"he",   :unexp=>INVCMD}
  tc << {:cmd=>"hel",  :unexp=>INVCMD}
  tc << {:cmd=>"help", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"hl",    :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"helpp", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "info breakpoints"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"i b",              :unexp=>INVCMD}
  tc << {:cmd=>"in  b",            :unexp=>INVCMD}
  tc << {:cmd=>"i    br",          :unexp=>INVCMD}
  tc << {:cmd=>"inf breakpoint",   :unexp=>INVCMD}
  tc << {:cmd=>"info breakpoints", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"ii b",              :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"i bb",              :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"infoo breakpoints", :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"info breakpointss", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "list"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"l",    :unexp=>INVCMD}
  tc << {:cmd=>"li",   :unexp=>INVCMD}
  tc << {:cmd=>"lis",  :unexp=>INVCMD}
  tc << {:cmd=>"list", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"ll",    :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"listt", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "print"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  tc = []
  tc << {:cmd=>"p",     :unexp=>INVCMD}
  tc << {:cmd=>"pr",    :unexp=>INVCMD}
  tc << {:cmd=>"prin",  :unexp=>INVCMD}
  tc << {:cmd=>"print", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"pp",     :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"printt", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "quit"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"q",    :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"qu",   :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"qui",  :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"quit", :unexp=>INVCMD}])

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"qq",    :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"quitt", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "run"') do
  # ruby source
  src = "foo = 'foo'\n"

  # test case
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"r",   :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"ru",  :unexp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"run", :unexp=>INVCMD}])

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"rr",   :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"runn", :exp=>INVCMD}])
end

assert('mruby-bin-debugger(mrdb) command: "step"') do
  # ruby source
  src = <<"SRC"
while true
  foo = 'foo'
end
SRC

  # test case
  tc = []
  tc << {:cmd=>"s",    :unexp=>INVCMD}
  tc << {:cmd=>"st",   :unexp=>INVCMD}
  tc << {:cmd=>"ste",  :unexp=>INVCMD}
  tc << {:cmd=>"step", :unexp=>INVCMD}
  BinTest_MrubyBinDebugger.test(src, tc)

  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"ss",    :exp=>INVCMD}])
  BinTest_MrubyBinDebugger.test(src, [{:cmd=>"stepp", :exp=>INVCMD}])
end
