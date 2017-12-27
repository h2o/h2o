MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  conf.enable_bintest
  conf.enable_test
  conf.gembox 'default'
  conf.gem '../mruby-class-new-fiber-safe'
end
