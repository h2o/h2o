MRuby::Gem::Specification.new('mruby-binding') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Binding class'

  spec.add_dependency('mruby-binding-core', :core => 'mruby-binding-core')
  spec.add_dependency('mruby-eval', :core => 'mruby-eval')
  spec.add_test_dependency('mruby-metaprog', :core => 'mruby-metaprog')
  spec.add_test_dependency('mruby-method', :core => 'mruby-method')
  spec.add_test_dependency('mruby-proc-ext', :core => 'mruby-proc-ext')
end
