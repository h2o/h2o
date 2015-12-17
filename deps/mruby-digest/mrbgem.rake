MRuby::Gem::Specification.new('mruby-digest') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Internet Initiative Japan Inc.'

  spec.linker.libraries << 'crypto' unless RUBY_PLATFORM =~ /darwin/
end
