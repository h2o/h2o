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
  config = "#{build_dir}/config.h"

  file config do
    FileUtils.mkdir_p build_dir, :verbose => true
    Dir.chdir build_dir do
      if ENV['OS'] == 'Windows_NT'
        _pp 'on Windows', dir
        FileUtils.touch "#{build_dir}/config.h", :verbose => true
      else
        _pp './configure', dir
        host = ''
        if build.kind_of?(MRuby::CrossBuild) && build.host_target
          host = "--host #{build.host_target}"
        end
        system env, "#{dir}/configure #{host}"
      end
    end
  end

  # build hook
  file "#{dir}/src/file-stat.c" => config

  task :clean do
    FileUtils.rm_f config, :verbose => true
  end

  cc.include_paths << build_dir
end
