require 'tempfile'

assert('Compiling multiple files without new line in last line. #2361') do
  a, b, out = Tempfile.new('a.rb'), Tempfile.new('b.rb'), Tempfile.new('out.mrb')
  a.write('module A; end')
  a.flush
  b.write('module B; end')
  b.flush
  result = `bin/mrbc -c -o #{out.path} #{a.path} #{b.path} 2>&1`
  assert_equal "bin/mrbc:#{a.path}:Syntax OK", result.chomp
  assert_equal 0, $?.exitstatus
end
