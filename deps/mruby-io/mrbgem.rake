MRuby::Gem::Specification.new('mruby-io') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Internet Initiative Japan Inc.'

  spec.cc.include_paths << "#{build.root}/src"
  
  case RUBY_PLATFORM
  when /mingw|mswin/
    spec.linker.libraries += ['Ws2_32']
    #spec.cc.include_paths += ["C:/Windows/system/include"]
    spec.linker.library_paths += ["C:/Windows/system"]
  end
  if build.kind_of?(MRuby::CrossBuild) && %w(x86_64-w64-mingw32 i686-w64-mingw32).include?(build.host_target)
    spec.linker.libraries += ['ws2_32']
  end
end
