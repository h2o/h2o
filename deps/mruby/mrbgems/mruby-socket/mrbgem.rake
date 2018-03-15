MRuby::Gem::Specification.new('mruby-socket') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Internet Initiative Japan'
  spec.summary = 'standard socket class'

  spec.cc.include_paths << "#{build.root}/src"

  # If Windows, use winsock
  if ( /mswin|mingw|win32/ =~ RUBY_PLATFORM ) then
    spec.linker.libraries << "wsock32"
    spec.linker.libraries << "ws2_32"
  end

  spec.add_dependency('mruby-io')
  spec.add_dependency('mruby-pack')
  # spec.add_dependency('mruby-mtest')
end
