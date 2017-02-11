MRuby::Gem::Specification.new('mruby-file-stat') do |spec|
  spec.license = 'MIT'
  spec.author  = 'ksss <co000ri@gmail.com>'
  spec.add_dependency('mruby-time')

  env = {
    'CC' => "#{build.cc.command} #{build.cc.flags.join(' ')}",
    'CXX' => "#{build.cxx.command} #{build.cxx.flags.join(' ')}",
    'LD' => "#{build.linker.command} #{build.linker.flags.join(' ')}",
    'AR' => build.archiver.command
  }
  config = "#{dir}/config.h"
  build_config = "#{build_dir}/config.h"

  file config do
    Dir.chdir dir do
      if ENV['OS'] == 'Windows_NT'
        _pp 'on Windows', dir
        FileUtils.touch "config.h", :verbose => true
      else
        _pp './configure', dir
        system env, "./configure"
      end
    end
  end
  file build_config => config do
    FileUtils.mkdir_p build_dir, :verbose => true
    FileUtils.cp config, build_config, :verbose => true
  end
  file "#{dir}/src/file-stat.c" => build_config
  task :clean do
    FileUtils.rm_f config, :verbose => true
  end

  cc.include_paths << build_dir
end
