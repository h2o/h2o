def gem_config(conf)
  conf.gem :core => "mruby-time"
  conf.gem '../'
end

MRuby::Build.new do |conf|
  toolchain :gcc
  conf.enable_test
  if ENV['DISABLE_PRESYM'] == 'true'
    conf.disable_presym
  end

  gem_config(conf)
end

if ENV['TARGET'] == 'windows-x86_64'
  MRuby::CrossBuild.new('windows-x86_64') do |conf|
    toolchain :gcc

    conf.cc.command       = 'x86_64-w64-mingw32-gcc'
    conf.linker.command   = 'x86_64-w64-mingw32-gcc'
    conf.cxx.command      = 'x86_64-w64-mingw32-g++'
    conf.archiver.command = 'x86_64-w64-mingw32-gcc-ar'

    conf.exts do |exts|
      exts.object = '.obj'
      exts.executable = '.exe'
      exts.library = '.lib'
    end

    conf.build_target     = 'x86_64-pc-linux-gnu'
    conf.host_target      = 'x86_64-w64-mingw32'

    gem_config(conf)
  end
end
