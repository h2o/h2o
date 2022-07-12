desc "build and run all mruby tests"
task :test => "test:build" do
  Rake::Task["test:run"].invoke
end

namespace :test do |test_ns|
  desc "build and run library tests"
  task :lib => "build:lib" do
    test_ns["run:lib"].invoke
  end

  desc "build and run command binaries tests"
  task :bin => "rake:all" do
    test_ns["run:bin"].invoke
  end

  desc "build all mruby tests"
  task :build => "build:lib"

  namespace :build do |test_build_ns|
    desc "build library tests"
    task :lib => "rake:all" do
      MRuby.each_target{|build| build.gem(core: 'mruby-test')}
      test = test_build_ns["lib_without_loading_gem"]
      test.invoke if test
    end
  end

  desc "run all mruby tests"
  task :run

  namespace :run do
    desc "run library tests"
    task :lib

    desc "run command binaries tests"
    task :bin
  end
end

MRuby.each_target do |build|
  if build.test_enabled?
    t = task "test:build:lib_without_loading_gem:#{build.name}" do
      gem = build.gems["mruby-test"]
      gem.setup
      gem.setup_compilers
      Rake::Task[build.define_installer_if_needed("mrbtest")].invoke
    end
    task "test:build:lib_without_loading_gem" => t

    t = task "test:run:lib:#{build.name}" do
      build.run_test
    end
    task "test:run" => t
    task "test:run:lib" => t
  end
  if build.bintest_enabled?
    t = task "test:run:bin:#{build.name}" do
      build.run_bintest
    end
    task "test:run" => t
    task "test:run:bin" => t
  end
end

task :clean do
  host = MRuby.targets["host"]
  rm_f host.exefile("#{host.class.install_dir}/mrbtest") if host && host.test_enabled?
end
