$dir = File.join(Dir.tmpdir, "mruby-require-test-#{Time.now.to_i}.#{Time.now.usec}")

def test_setup
  Dir.mkdir($dir)

  File.open(File.join($dir, "loop1.rb"), "w") do |fp|
    fp.puts "require 'loop2.rb'"
    fp.puts "$loop1 = 'loop1'"
  end
  File.open(File.join($dir, "loop2.rb"), "w") do |fp|
    fp.puts "require 'loop1.rb'"
    fp.puts "$loop2 = 'loop2'"
  end

  $require_test_count = 10
  (1..$require_test_count-1).each do |i|
    File.open(File.join($dir, "#{i+1}.rb"), "w") do |fp|
      fp.puts "require '#{i}'"
      fp.puts "s = 0"
      (0..100).each{|num| fp.puts "s += #{num}" }
    end
  end
  File.open(File.join($dir, "1.rb"), "w") do |fp|
    fp.puts "$require_test_0 = 123"
  end

  $LOAD_PATH = [$dir]
end

def test_cleanup
  if $dir && File.exist?($dir)
    Dir.entries($dir).each do |e|
      next if ['.', '..'].include? e
      File.unlink File.join($dir,e)
    end
    Dir.unlink $dir
  end
end

#####
test_setup
#####

assert("require loop check") do
  require 'loop1'
  assert_equal 'loop1', $loop1
  assert_equal 'loop2', $loop2
end

assert("require nest") do
  before = $".size
  require "#{$require_test_count}"
  assert_equal before + $require_test_count, $".size
end

#####
test_cleanup
#####
