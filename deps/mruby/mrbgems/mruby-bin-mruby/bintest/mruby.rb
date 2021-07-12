require 'tempfile'
require 'open3'

def assert_mruby(exp_out, exp_err, exp_success, args)
  out, err, stat = Open3.capture3(cmd("mruby"), *args)
  assert "assert_mruby" do
    assert_operator(exp_out, :===, out, "standard output")
    assert_operator(exp_err, :===, err, "standard error")
    assert_equal(exp_success, stat.success?, "exit success?")
  end
end

assert('regression for #1564') do
  assert_mruby("", /\A-e:1:2: syntax error, .*\n\z/, false, %w[-e <<])
  assert_mruby("", /\A-e:1:3: syntax error, .*\n\z/, false, %w[-e <<-])
end

assert('regression for #1572') do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')
  File.write script.path, 'p "ok"'
  system "#{cmd('mrbc')} -g -o #{bin.path} #{script.path}"
  o = `#{cmd('mruby')} -b #{bin.path}`.strip
  assert_equal '"ok"', o
end

assert '$0 value' do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')

  # .rb script
  script.write "p $0\n"
  script.flush
  assert_equal "\"#{script.path}\"", `#{cmd('mruby')} "#{script.path}"`.chomp

  # .mrb file
  `#{cmd('mrbc')} -o "#{bin.path}" "#{script.path}"`
  assert_equal "\"#{bin.path}\"", `#{cmd('mruby')} -b "#{bin.path}"`.chomp

  # one liner
  assert_equal '"-e"', `#{cmd('mruby')} -e #{shellquote('p $0')}`.chomp
end

assert 'ARGV value' do
  assert_mruby(%{["ab", "cde"]\n}, "", true, %w[-e p(ARGV) ab cde])
  assert_mruby("[]\n", "", true, %w[-e p(ARGV)])
end

assert('float literal') do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')
  File.write script.path, 'p [3.21, 2e308.infinite?, -2e308.infinite?]'
  system "#{cmd('mrbc')} -g -o #{bin.path} #{script.path}"
  assert_equal "[3.21, 1, -1]", `#{cmd('mruby')} -b #{bin.path}`.chomp!
end

assert '__END__', '8.6' do
  script = Tempfile.new('test.rb')

  script.write <<EOS
p 'test'
  __END__ = 'fin'
p __END__
__END__
p 'legend'
EOS
  script.flush
  assert_equal "\"test\"\n\"fin\"\n", `#{cmd('mruby')} #{script.path}`
end

assert('garbage collecting built-in classes') do
  script = Tempfile.new('test.rb')

  script.write <<RUBY
NilClass = nil
GC.start
Array.dup
print nil.class.to_s
RUBY
  script.flush
  assert_equal "NilClass", `#{cmd('mruby')} #{script.path}`
  assert_equal 0, $?.exitstatus
end

assert('mruby -c option') do
  assert_mruby("Syntax OK\n", "", true, ["-c", "-e", "p 1"])
  assert_mruby("", /\A-e:1:7: syntax error, .*\n\z/, false, ["-c", "-e", "p 1; 1."])
end

assert('mruby -d option') do
  assert_mruby("false\n", "", true, ["-e", "p $DEBUG"])
  assert_mruby("true\n", "", true, ["-dep $DEBUG"])
end

assert('mruby -e option (no code specified)') do
  assert_mruby("", /\A.*: No code specified for -e\n\z/, false, %w[-e])
end

assert('mruby -h option') do
  assert_mruby(/\AUsage: #{Regexp.escape cmd("mruby")} .*/m, "", true, %w[-h])
end

assert('mruby -r option') do
  lib = Tempfile.new('lib.rb')
  lib.write <<EOS
class Hoge
  def hoge
    :hoge
  end
end
EOS
  lib.flush

  script = Tempfile.new('test.rb')
  script.write <<EOS
print Hoge.new.hoge
EOS
  script.flush
  assert_equal 'hoge', `#{cmd('mruby')} -r #{lib.path} #{script.path}`
  assert_equal 0, $?.exitstatus

  assert_equal 'hogeClass', `#{cmd('mruby')} -r #{lib.path} -r #{script.path} -e #{shellquote('print Hoge.class')}`
  assert_equal 0, $?.exitstatus
end

assert('mruby -r option (no library specified)') do
  assert_mruby("", /\A.*: No library specified for -r\n\z/, false, %w[-r])
end

assert('mruby -r option (file not found)') do
  assert_mruby("", /\A.*: Cannot open library file: .*\n\z/, false, %w[-r _no_exists_])
end

assert('mruby -v option') do
  ver_re = '\Amruby \d+\.\d+\.\d+ \(\d+-\d+-\d+\)\n'
  assert_mruby(/#{ver_re}\z/, "", true, %w[-v])
  assert_mruby(/#{ver_re}^[^\n]*NODE.*\n:end\n\z/m, "", true, %w[-v -e p(:end)])
end

assert('mruby --verbose option') do
  assert_mruby(/\A[^\n]*NODE.*\n:end\n\z/m, "", true, %w[--verbose -e p(:end)])
end

assert('mruby --') do
  assert_mruby(%{["-x", "1"]\n}, "", true, %w[-e p(ARGV) -- -x 1])
end

assert('mruby invalid short option') do
  assert_mruby("", /\A.*: invalid option -1 .*\n\z/, false, %w[-1])
end

assert('mruby invalid long option') do
  assert_mruby("", /\A.*: invalid option --longopt .*\n\z/, false, %w[--longopt])
end

assert('unhandled exception') do
  assert_mruby("", /\bEXCEPTION\b.*\n\z/, false, %w[-e raise("EXCEPTION")])
end

assert('program file not found') do
  assert_mruby("", /\A.*: Cannot open program file: .*\n\z/, false, %w[_no_exists_])
end

assert('codegen error') do
  code = "def f(#{(1..100).map{|n| "a#{n}"} * ","}); end"
  assert_mruby("", /\Acodegen error:.*\n\z/, false, ["-e", code])
end
