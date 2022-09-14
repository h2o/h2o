require 'open3'
require 'tempfile'

assert('mirb normal operations') do
  o, s = Open3.capture2(cmd("mirb"), :stdin_data => "a=1\nb=2\na+b\n")
  assert_true o.include?('=> 3')
  assert_true o.include?('=> 2')
end

assert('regression for #1563') do
  o, s = Open3.capture2(cmd("mirb"), :stdin_data => "a=1;b=2;c=3\nb\nc")
  assert_true o.include?('=> 3')
end

assert('mirb -d option') do
  o, _ = Open3.capture2(cmd("mirb"), :stdin_data => "$DEBUG\n")
  assert_true o.include?('=> false')
  o, _ = Open3.capture2("#{cmd('mirb')} -d", :stdin_data => "$DEBUG\n")
  assert_true o.include?('=> true')
end

assert('mirb -r option') do
  lib = Tempfile.new('lib.rb')
  lib.write <<EOS
class Hoge
  def hoge
    :hoge
  end
end
EOS
  lib.flush

  o, _ = Open3.capture2("#{cmd('mirb')} -r #{lib.path}", :stdin_data => "Hoge.new.hoge\n")
  assert_true o.include?('=> :hoge')
end

assert('top level local variables are in file scope') do
  lib = Tempfile.new('lib.rb')
  lib.write <<-TESTLIB
a = 1
A = -> { a }
  TESTLIB
  lib.flush

  o, _ = Open3.capture2("#{cmd('mirb')} -r #{lib.path}", :stdin_data => <<-TESTCODE)
a
a = 5
A.call
  TESTCODE

  assert_kind_of Integer, o =~ /\bundefined method 'a' \(NoMethodError\).*=> 5\b.*=> 1\b/m
end
