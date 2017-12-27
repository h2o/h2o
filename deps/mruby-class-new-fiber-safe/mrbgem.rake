MRuby::Gem::Specification.new('mruby-class-new-fiber-safe') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers, Kazuho Oku'
  spec.version = '0.0.1'
  spec.add_dependency('mruby-fiber', :core => 'mruby-fiber')
  spec.summary = 'Class#new that allows use of fiber in constructor'
end
