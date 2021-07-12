MRuby::Gem::Specification.new('mruby-complex') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Complex class'

  spec.add_dependency 'mruby-math', core: 'mruby-math'
end
