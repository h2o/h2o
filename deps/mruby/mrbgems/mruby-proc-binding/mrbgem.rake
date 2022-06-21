MRuby::Gem::Specification.new('mruby-proc-binding') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Proc#binding method'

  spec.add_dependency('mruby-binding-core', :core => 'mruby-binding-core')
  spec.add_test_dependency('mruby-binding', :core => 'mruby-binding')
  spec.add_test_dependency('mruby-compiler', :core => 'mruby-compiler')
end
