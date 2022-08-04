# encoding: utf-8
# Build description.
# basic build file for mruby
MRUBY_ROOT = File.dirname(File.expand_path(__FILE__))
MRUBY_BUILD_HOST_IS_CYGWIN = RUBY_PLATFORM.include?('cygwin')
MRUBY_BUILD_HOST_IS_OPENBSD = RUBY_PLATFORM.include?('openbsd')

Rake.verbose(false) if Rake.verbose == Rake::DSL::DEFAULT

$LOAD_PATH << File.join(MRUBY_ROOT, "lib")

# load build systems
require "mruby/core_ext"
require "mruby/build"

# load configuration file
MRUBY_CONFIG = MRuby::Build.mruby_config_path
load MRUBY_CONFIG

# load basic rules
MRuby.each_target do |build|
  build.define_rules
end

# load custom rules
load "#{MRUBY_ROOT}/tasks/core.rake"
load "#{MRUBY_ROOT}/tasks/mrblib.rake"
load "#{MRUBY_ROOT}/tasks/mrbgems.rake"
load "#{MRUBY_ROOT}/tasks/libmruby.rake"
load "#{MRUBY_ROOT}/tasks/bin.rake"
load "#{MRUBY_ROOT}/tasks/presym.rake"
load "#{MRUBY_ROOT}/tasks/test.rake"
load "#{MRUBY_ROOT}/tasks/benchmark.rake"
load "#{MRUBY_ROOT}/tasks/doc.rake"

##############################
# generic build targets, rules
task :default => :all

desc "build all targets, install (locally) in-repo"
task :all => :gensym do
  Rake::Task[:build].invoke
  puts
  puts "Build summary:"
  puts
  MRuby.each_target do |build|
    build.print_build_summary
  end
  MRuby::Lockfile.write
end

task :build => MRuby.targets.flat_map{|_, build| build.products}

desc "clean all built and in-repo installed artifacts"
task :clean do
  MRuby.each_target do |build|
    rm_rf build.build_dir
    rm_f build.products
  end
  puts "Cleaned up target build folder"
end

desc "clean everything!"
task :deep_clean => %w[clean doc:clean] do
  MRuby.each_target do |build|
    rm_rf build.gem_clone_dir
  end
  puts "Cleaned up mrbgems build folder"
end

PREFIX = ENV['PREFIX'] || ENV['INSTALL_PREFIX'] || '/usr/local'

desc "install compiled products"
task :install => :install_bin do
  if host = MRuby.targets['host']
    install_D host.libmruby_static, File.join(PREFIX, "lib", File.basename(host.libmruby_static))
    # install mruby.h and mrbconf.h
    Dir.glob(File.join(MRUBY_ROOT, "include", "*.h")) do |src|
      install_D src, File.join(PREFIX, "include", File.basename(src))
    end
    Dir.glob(File.join(MRUBY_ROOT, "include", "mruby", "*.h")) do |src|
      install_D src, File.join(PREFIX, "include", "mruby", File.basename(src))
    end
    Dir.glob(File.join(File.join(MRUBY_ROOT, "build", "host", "include", "mruby", "presym", "*.h"))) do |src|
      install_D src, File.join(PREFIX, "include", "mruby", "presym", File.basename(src))
    end
  end
end

desc "install compiled executable (on host)"
task :install_bin => :all do
  if host = MRuby.targets['host']
    Dir.glob(File.join(MRUBY_ROOT, "bin", "*")) do |src|
      install_D src, File.join(PREFIX, "bin", File.basename(src))
    end
  end
end
