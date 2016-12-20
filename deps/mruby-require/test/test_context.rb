$dir = File.join(Dir.tmpdir, "mruby-require-test-#{Time.now.to_i}.#{Time.now.usec}")

def test_setup
  Dir.mkdir($dir) unless File.exist?($dir)

  File.open(File.join($dir, "foo.rb"), "w") do |f|
    f.puts "$require_context = self"
  end
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

assert("require context") do
  require File.join($dir, 'foo.rb')
  assert_equal self, $require_context
end

#####
test_cleanup
#####
