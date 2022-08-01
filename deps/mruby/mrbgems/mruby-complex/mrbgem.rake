MRuby::Gem::Specification.new('mruby-complex') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Complex class'
  spec.build.defines << "MRB_USE_COMPLEX"
  spec.add_dependency 'mruby-math', core: 'mruby-math'
end
