MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem "#{MRUBY_ROOT}/.."
end

MRuby::Build.new("onigmo-bundled") do |conf|
  toolchain :gcc
  enable_debug

  gem :core => 'mruby-print'
  gem :core => 'mruby-sprintf'
  gem "#{MRUBY_ROOT}/.." do |g|
    g.bundle_onigmo
  end
end
