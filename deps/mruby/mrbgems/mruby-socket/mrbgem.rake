MRuby::Gem::Specification.new('mruby-socket') do |spec|
  spec.license = 'MIT'
  spec.authors = ['Internet Initiative Japan', 'mruby developers']
  spec.summary = 'standard socket class'

  spec.cc.include_paths << "#{build.root}/src"
  #spec.cc.defines << "HAVE_SA_LEN=0"

  # If Windows, use winsock
  if spec.for_windows?
    spec.linker.libraries << "wsock32"
    spec.linker.libraries << "ws2_32"
  end

  spec.add_dependency('mruby-io', :core => 'mruby-io')
  spec.add_dependency('mruby-pack', :core => 'mruby-pack')
  # spec.add_dependency('mruby-mtest')
end
