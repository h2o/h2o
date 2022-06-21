MRuby::Gem::Specification.new('mruby-rational') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Rational class'
  spec.build.defines << "MRB_USE_RATIONAL"
  spec.add_test_dependency('mruby-complex')
end
