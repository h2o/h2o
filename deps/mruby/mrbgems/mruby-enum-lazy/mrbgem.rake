MRuby::Gem::Specification.new('mruby-enum-lazy') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Enumerator::Lazy class'
  spec.add_dependency('mruby-enumerator', :core => 'mruby-enumerator')
  spec.add_dependency('mruby-enum-ext', :core => 'mruby-enum-ext')
end
