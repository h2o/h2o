MRuby::Gem::Specification.new('mruby-os-memsize') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'ObjectSpace memsize_of method'

  spec.add_dependency('mruby-objectspace')
  spec.add_test_dependency('mruby-metaprog')
  spec.add_test_dependency('mruby-method')
  spec.add_test_dependency('mruby-fiber')
end
