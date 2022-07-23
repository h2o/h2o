MRuby::Gem::Specification.new('mruby-pack') do |spec|
  spec.license = 'MIT'
  spec.authors = ['Internet Initiative Japan Inc.', 'mruby developers']
  spec.summary = 'Array#pack and String#unpack method'

  spec.cc.include_paths << "#{build.root}/src"
end
