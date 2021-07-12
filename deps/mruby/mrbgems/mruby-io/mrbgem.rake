MRuby::Gem::Specification.new('mruby-io') do |spec|
  spec.license = 'MIT'
  spec.authors = ['Internet Initiative Japan Inc.', 'mruby developers']
  spec.summary = 'IO and File class'

  spec.cc.include_paths << "#{build.root}/src"

  if for_windows?
    spec.linker.libraries << "ws2_32"
  end
  spec.add_test_dependency 'mruby-time', core: 'mruby-time'
end
