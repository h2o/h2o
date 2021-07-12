MRuby::Toolchain.new(:clang) do |conf, _params|
  toolchain :gcc, default_command: 'clang'

  [conf.cc, conf.objc, conf.asm].each do |cc|
    cc.flags << '-Wzero-length-array' unless ENV['CFLAGS']
  end
  conf.cxx.flags << '-Wzero-length-array' unless ENV['CXXFLAGS'] || ENV['CFLAGS']
end
