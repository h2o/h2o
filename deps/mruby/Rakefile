# encoding: utf-8
# Build description.
# basic build file for mruby
MRUBY_ROOT = File.dirname(File.expand_path(__FILE__))
MRUBY_BUILD_HOST_IS_CYGWIN = RUBY_PLATFORM.include?('cygwin')
MRUBY_BUILD_HOST_IS_OPENBSD = RUBY_PLATFORM.include?('openbsd')

$LOAD_PATH << File.join(MRUBY_ROOT, "lib")

# load build systems
require "mruby-core-ext"
require "mruby/build"
require "mruby/gem"

# load configuration file
MRUBY_CONFIG = (ENV['MRUBY_CONFIG'] && ENV['MRUBY_CONFIG'] != '') ? ENV['MRUBY_CONFIG'] : "#{MRUBY_ROOT}/build_config.rb"
load MRUBY_CONFIG

# load basic rules
MRuby.each_target do |build|
  build.define_rules
end

# load custom rules
load "#{MRUBY_ROOT}/src/mruby_core.rake"
load "#{MRUBY_ROOT}/mrblib/mrblib.rake"

load "#{MRUBY_ROOT}/tasks/mrbgems.rake"
load "#{MRUBY_ROOT}/tasks/libmruby.rake"

load "#{MRUBY_ROOT}/tasks/benchmark.rake"

load "#{MRUBY_ROOT}/tasks/gitlab.rake"

##############################
# generic build targets, rules
task :default => :all

bin_path = ENV['INSTALL_DIR'] || "#{MRUBY_ROOT}/bin"
FileUtils.mkdir_p bin_path, { :verbose => $verbose }

depfiles = MRuby.targets['host'].bins.map do |bin|
  install_path = MRuby.targets['host'].exefile("#{bin_path}/#{bin}")
  source_path = MRuby.targets['host'].exefile("#{MRuby.targets['host'].build_dir}/bin/#{bin}")

  file install_path => source_path do |t|
    FileUtils.rm_f t.name, { :verbose => $verbose }
    FileUtils.cp t.prerequisites.first, t.name, { :verbose => $verbose }
  end

  install_path
end

MRuby.each_target do |target|
  gems.map do |gem|
    current_dir = gem.dir.relative_path_from(Dir.pwd)
    relative_from_root = gem.dir.relative_path_from(MRUBY_ROOT)
    current_build_dir = File.expand_path "#{build_dir}/#{relative_from_root}"

    if current_build_dir !~ /^#{build_dir}/
      current_build_dir = "#{build_dir}/mrbgems/#{gem.name}"
    end

    gem.bins.each do |bin|
      exec = exefile("#{build_dir}/bin/#{bin}")
      objs = Dir.glob("#{current_dir}/tools/#{bin}/*.{c,cpp,cxx,cc}").map { |f| objfile(f.pathmap("#{current_build_dir}/tools/#{bin}/%n")) }

      file exec => objs + [libfile("#{build_dir}/lib/libmruby")] do |t|
        gem_flags = gems.map { |g| g.linker.flags }
        gem_flags_before_libraries = gems.map { |g| g.linker.flags_before_libraries }
        gem_flags_after_libraries = gems.map { |g| g.linker.flags_after_libraries }
        gem_libraries = gems.map { |g| g.linker.libraries }
        gem_library_paths = gems.map { |g| g.linker.library_paths }
        linker.run t.name, t.prerequisites, gem_libraries, gem_library_paths, gem_flags, gem_flags_before_libraries, gem_flags_after_libraries
      end

      if target == MRuby.targets['host']
        install_path = MRuby.targets['host'].exefile("#{bin_path}/#{bin}")

        file install_path => exec do |t|
          FileUtils.rm_f t.name, { :verbose => $verbose }
          FileUtils.cp t.prerequisites.first, t.name, { :verbose => $verbose }
        end
        depfiles += [ install_path ]
      elsif target == MRuby.targets['host-debug']
        unless MRuby.targets['host'].gems.map {|g| g.bins}.include?([bin])
          install_path = MRuby.targets['host-debug'].exefile("#{bin_path}/#{bin}")

          file install_path => exec do |t|
            FileUtils.rm_f t.name, { :verbose => $verbose }
            FileUtils.cp t.prerequisites.first, t.name, { :verbose => $verbose }
          end
          depfiles += [ install_path ]
        end
      else
        depfiles += [ exec ]
      end
    end
  end
end

depfiles += MRuby.targets.map { |n, t|
  [t.libfile("#{t.build_dir}/lib/libmruby")]
}.flatten

depfiles += MRuby.targets.reject { |n, t| n == 'host' }.map { |n, t|
  t.bins.map { |bin| t.exefile("#{t.build_dir}/bin/#{bin}") }
}.flatten

desc "build all targets, install (locally) in-repo"
task :all => depfiles do
  puts
  puts "Build summary:"
  puts
  MRuby.each_target do
    print_build_summary
  end
end

desc "run all mruby tests"
MRuby.each_target do
  next unless test_enabled?

  t = :"test_#{self.name}"
  task t => ["all"] do
    run_test
  end
  task :test => t

  next unless bintest_enabled?
  t = :"bintest_#{self.name}"
  task t => ["all"] do
    run_bintest
  end
  task :test => t
end

desc "clean all built and in-repo installed artifacts"
task :clean do
  MRuby.each_target do |t|
    FileUtils.rm_rf t.build_dir, { :verbose => $verbose }
  end
  FileUtils.rm_f depfiles, { :verbose => $verbose }
  puts "Cleaned up target build folder"
end

desc "clean everything!"
task :deep_clean => ["clean"] do
  MRuby.each_target do |t|
    FileUtils.rm_rf t.gem_clone_dir, { :verbose => $verbose }
  end
  puts "Cleaned up mrbgems build folder"
end

desc 'generate document'
task :doc do
  begin
    sh "mrbdoc"
  rescue
    puts "ERROR: To generate documents, you should install yard-mruby gem."
    puts "  $ gem install yard-mruby"
  end
end
