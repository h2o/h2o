MRuby::Gem::Specification.new('mruby-mtest') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Internet Initiative Japan Inc.'

  spec.add_dependency 'mruby-sprintf', core: 'mruby-sprintf'
  spec.add_dependency 'mruby-time', core: 'mruby-time'
  spec.add_dependency 'mruby-io', mgem: 'mruby-io'
end
