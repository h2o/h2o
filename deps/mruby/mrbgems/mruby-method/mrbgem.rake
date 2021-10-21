MRuby::Gem::Specification.new('mruby-method') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'Method and UnboundMethod class'

  spec.add_dependency('mruby-proc-ext', :core => 'mruby-proc-ext')
end
