MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem "#{MRUBY_ROOT}/.."
end
