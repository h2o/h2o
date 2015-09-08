MRuby::Gem::Specification.new('mruby-dir') do |spec|
  spec.license = 'MIT and MIT-like license'
  spec.authors = [ 'Internet Initiative Japan Inc.', 'Kevlin Henney']

  spec.cc.include_paths << "#{build.root}/src"
end
