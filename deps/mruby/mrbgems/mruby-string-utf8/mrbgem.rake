MRuby::Gem::Specification.new('mruby-string-utf8') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'UTF-8 support in String class'
  spec.add_dependency('mruby-string-ext', :core => 'mruby-string-ext')
end
