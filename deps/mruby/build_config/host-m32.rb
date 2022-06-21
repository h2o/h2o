MRuby::Build.new do |conf|
  # load specific toolchain settings
  toolchain :gcc

  # include the GEM box
  conf.gembox 'default'

  conf.cc.flags << '-m32'
  conf.linker.flags << '-m32'

  # Turn on `enable_debug` for better debugging
  conf.enable_debug
  conf.enable_test
  conf.enable_bintest
end
