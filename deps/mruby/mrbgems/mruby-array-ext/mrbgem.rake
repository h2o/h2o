MRuby::Gem::Specification.new('mruby-array-ext') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Array class extension'
  spec.add_test_dependency 'mruby-enumerator', core: 'mruby-enumerator'
end
