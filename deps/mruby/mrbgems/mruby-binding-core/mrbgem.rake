MRuby::Gem::Specification.new('mruby-binding-core') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Binding class (core features only)'

  spec.add_test_dependency('mruby-proc-ext', :core => 'mruby-proc-ext')
end
