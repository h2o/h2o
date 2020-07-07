MRuby::Gem::Specification.new('mruby-enumerator') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.add_dependency('mruby-fiber', :core => 'mruby-fiber')
  spec.summary = 'Enumerator class'
end
