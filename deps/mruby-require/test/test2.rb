$dir = File.join(Dir.tmpdir, "mruby-require-test-#{Time.now.to_i}.#{Time.now.usec}")

def test_setup
  Dir.mkdir($dir)  unless File.exist?($dir)

  File.open(File.join($dir, "test.rb"), "w") do |fp|
    fp.puts "$require_test_variable = 123"
  end

  File.open(File.join($dir, "test_dir.rb"), "w") do |fp|
    fp.puts "$test_dir = 'test_dir'"
  end
  Dir.mkdir(File.join($dir, "test_dir"))
  File.open(File.join($dir, "test_dir", "test_dir.rb"), "w") do |fp|
    fp.puts "$test_dir2 = 'test_dir/test_dir'"
  end

  File.open(File.join($dir, "test_conf.conf"), "w") do |fp|
    fp.puts "$test_conf = 'test_conf'"
  end

  File.open(File.join($dir, "empty.rb"), "w")

  test_reset
end

def test_reset
  $require_test_variable = nil
  $test_dir = nil
  $test_dir2 = nil
  $test_conf = nil
  $LOAD_PATH = [$dir]
  $" = []
end

def remove_file_recursive(path)
  if File.directory? path
    Dir.entries(path).each do |entry|
      next if ['.', '..'].include?(entry)
      remove_file_recursive File.join(path, entry)
    end
    Dir.unlink path
  else
    File.unlink path
  end
end

def test_cleanup
  if $dir && File.exist?($dir)
    remove_file_recursive $dir
  end
end

#####
test_setup
#####

assert("require 'test' should be success") do
  test_reset

  assert_true require("test"), "require returns true when success"
  assert_equal [File.join($dir, "test.rb")], $"
  assert_equal 123, $require_test_variable
  $require_test_variable = 789
  assert_false require("test"), "2nd require should returns false"
  assert_equal 789, $require_test_variable

  test_reset

  assert_true require("test.rb"), "require should be success with '.rb'"
  assert_equal [File.join($dir, "test.rb")], $"
end

assert("require with absolute path should be success") do
  test_reset
  assert_true require(File.join($dir, "test"))
  assert_equal [File.join($dir, "test.rb")], $"

  test_reset
  assert_true require(File.join($dir, "test.rb"))
  assert_equal [File.join($dir, "test.rb")], $"
end

assert("require with absolute path && empty load_path") do
  test_reset
  $LOAD_PATH = []

  assert_raise LoadError, "cannot load test.rb" do
    require "test"
  end
  assert_equal true, require(File.join($dir, "test"))
end

assert("require 'test_dir' should be success") do
  test_reset

  assert_true require("test_dir"), "require 'test_dir' should be load 'test_dir.rb'"
  assert_equal [File.join($dir, "test_dir.rb")], $"
  assert_true require("test_dir/test_dir"), "require 'test_dir/test_dir' should be success"
  assert_equal 'test_dir/test_dir', $test_dir2
end

assert("require 'test_conf' should be fail") do
  test_reset

  assert_raise LoadError, "require 'test_conf.conf' should be fail" do
    require("test_conf.conf")
  end
  assert_raise LoadError, "require method can't load *.conf" do
    require File.join($dir, "test_conf.conf")
  end
end

assert("require 'empty' should be success") do
  test_reset

  assert_true require("empty")
  assert_equal 0, File.size(File.join($dir, "empty.rb"))
end

assert("load 'test.rb' should be success") do
  test_reset

  assert_true load(File.join($dir, "test.rb"))
  assert_equal 123, $require_test_variable
  assert_true $".empty?
end

assert("load 'test_conf.conf' should be success") do
  test_reset

  assert_equal true, load(File.join($dir, "test_conf.conf"))
  assert_equal "test_conf", $test_conf
end


#####
test_cleanup
#####
