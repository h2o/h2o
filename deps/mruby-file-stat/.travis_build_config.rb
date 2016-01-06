MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'
  conf.enable_test

  conf.gem '../mruby-file-stat'
end
