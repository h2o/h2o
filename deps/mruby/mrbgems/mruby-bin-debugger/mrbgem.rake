MRuby::Gem::Specification.new('mruby-bin-debugger') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby debuggeer command'

  spec.add_dependency('mruby-eval', :core => 'mruby-eval')

  spec.bins = %w(mrdb)
end
