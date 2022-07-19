MRuby::Build.new do |conf|
  conf.toolchain :clang
  # include the GEM box
  conf.gembox 'full-core'

  # Turn on `enable_debug` for better debugging
  conf.enable_sanitizer "address,undefined"
  conf.enable_debug
  conf.enable_bintest
  conf.enable_test
end
