MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  enable_test # IMPORTANT!

  gem :core => 'mruby-print'
  gem File.expand_path(File.dirname(__FILE__))
end
