MRuby::Build.new do |conf|
  # load specific toolchain settings
  toolchain :gcc

  # include the GEM box
  conf.gembox 'full-core'

  conf.cc.flags << '-pg'
  conf.linker.flags << '-pg'

  # Turn on `enable_debug` for better debugging
  conf.enable_debug
  conf.enable_test
end
