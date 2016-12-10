require 'tempfile'

assert('Compiling multiple files without new line in last line. #2361') do
  a, b, out = Tempfile.new('a.rb'), Tempfile.new('b.rb'), Tempfile.new('out.mrb')
  a.write('module A; end')
  a.flush
  b.write('module B; end')
  b.flush
  result = `#{cmd('mrbc')} -c -o #{out.path} #{a.path} #{b.path} 2>&1`
  assert_equal "#{cmd('mrbc')}:#{a.path}:Syntax OK", result.chomp
  assert_equal 0, $?.exitstatus
end

assert('parsing function with void argument') do
  a, out = Tempfile.new('a.rb'), Tempfile.new('out.mrb')
  a.write('f ()')
  a.flush
  result = `#{cmd('mrbc')} -c -o #{out.path} #{a.path} 2>&1`
  assert_equal "#{cmd('mrbc')}:#{a.path}:Syntax OK", result.chomp
  assert_equal 0, $?.exitstatus
end
