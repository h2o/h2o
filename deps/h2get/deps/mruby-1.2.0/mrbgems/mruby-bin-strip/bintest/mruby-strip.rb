require 'tempfile'

assert('no files') do
  o = `#{cmd('mruby-strip')} 2>&1`
  assert_equal 1, $?.exitstatus
  assert_equal "no files to strip", o.split("\n")[0]
end

assert('file not found') do
  o = `#{cmd('mruby-strip')} not_found.mrb 2>&1`
  assert_equal 1, $?.exitstatus
  assert_equal "can't open file for reading not_found.mrb\n", o
end

assert('not irep file') do
  t = Tempfile.new('script.rb')
  t.write 'p test\n'
  t.flush
  o = `#{cmd('mruby-strip')} #{t.path} 2>&1`
  assert_equal 1, $?.exitstatus
  assert_equal "can't read irep file #{t.path}\n", o
end

assert('success') do
  script_file, compiled1, compiled2 =
    Tempfile.new('script.rb'), Tempfile.new('c1.mrb'), Tempfile.new('c2.mrb')
  script_file.write "p 'test'\n"
  script_file.flush
  `#{cmd('mrbc')} -g -o #{compiled1.path} #{script_file.path}`
  `#{cmd('mrbc')} -g -o #{compiled2.path} #{script_file.path}`

  o = `#{cmd('mruby-strip')} #{compiled1.path}`
  assert_equal 0, $?.exitstatus
  assert_equal "", o
  assert_equal `#{cmd('mruby')} #{script_file.path}`, `#{cmd('mruby')} -b #{compiled1.path}`

  o = `#{cmd('mruby-strip')} #{compiled1.path} #{compiled2.path}`
  assert_equal 0, $?.exitstatus
  assert_equal "", o
end

assert('check debug section') do
  script_file, with_debug, without_debug =
    Tempfile.new('script.rb'), Tempfile.new('c1.mrb'), Tempfile.new('c2.mrb')
  script_file.write "p 'test'\n"
  script_file.flush
  `#{cmd('mrbc')} -o #{without_debug.path} #{script_file.path}`
  `#{cmd('mrbc')} -g -o #{with_debug.path} #{script_file.path}`

  assert_true with_debug.size >= without_debug.size

  `#{cmd('mruby-strip')} #{with_debug.path}`
  assert_equal without_debug.size, with_debug.size
end

assert('check lv section') do
  script_file, with_lv, without_lv =
    Tempfile.new('script.rb'), Tempfile.new('c1.mrb'), Tempfile.new('c2.mrb')
  script_file.write <<EOS
a, b = 0, 1
a += b
p Kernel.local_variables
EOS
  script_file.flush
  `#{cmd('mrbc')} -o #{with_lv.path} #{script_file.path}`
  `#{cmd('mrbc')} -o #{without_lv.path} #{script_file.path}`

  `#{cmd('mruby-strip')} -l #{without_lv.path}`
  assert_true without_lv.size < with_lv.size

  assert_equal '[:a, :b]', `#{cmd('mruby')} -b #{with_lv.path}`.chomp
  assert_equal '[]', `#{cmd('mruby')} -b #{without_lv.path}`.chomp
end
