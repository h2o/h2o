require 'tempfile'

assert('regression for #1564') do
  o = `#{cmd('mruby')} -e #{shellquote('<<')} 2>&1`
  assert_include o, "-e:1:2: syntax error"
  o = `#{cmd('mruby')} -e #{shellquote('<<-')} 2>&1`
  assert_include o, "-e:1:3: syntax error"
end

assert('regression for #1572') do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')
  File.write script.path, 'p "ok"'
  system "#{cmd('mrbc')} -g -o #{bin.path} #{script.path}"
  o = `#{cmd('mruby')} -b #{bin.path}`.strip
  assert_equal o, '"ok"'
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

assert('mruby -d option') do
  o = `#{cmd('mruby')} -e #{shellquote('p $DEBUG')}`
  assert_equal "false\n", o
  o = `#{cmd('mruby')} -d -e #{shellquote('p $DEBUG')}`
  assert_equal "true\n", o
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
