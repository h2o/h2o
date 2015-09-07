require 'tempfile'

assert('regression for #1564') do
  o = `bin/mruby -e '<<' 2>&1`
  assert_equal o, "-e:1:2: syntax error, unexpected tLSHFT\n"
  o = `bin/mruby -e '<<-' 2>&1`
  assert_equal o, "-e:1:3: syntax error, unexpected tLSHFT\n"
end

assert('regression for #1572') do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')
  system "echo 'p \"ok\"' > #{script.path}"
  system "bin/mrbc -g -o #{bin.path} #{script.path}"
  o = `bin/mruby -b #{bin.path}`.strip
  assert_equal o, '"ok"'
end

assert '$0 value' do
  script, bin = Tempfile.new('test.rb'), Tempfile.new('test.mrb')

  # .rb script
  script.write "p $0\n"
  script.flush
  assert_equal "\"#{script.path}\"", `./bin/mruby "#{script.path}"`.chomp

  # .mrb file
  `./bin/mrbc -o "#{bin.path}" "#{script.path}"`
  assert_equal "\"#{bin.path}\"", `./bin/mruby -b "#{bin.path}"`.chomp

  # one liner
  assert_equal '"-e"', `./bin/mruby -e 'p $0'`.chomp
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
  assert_equal "\"test\"\n\"fin\"\n", `./bin/mruby #{script.path}`
end
