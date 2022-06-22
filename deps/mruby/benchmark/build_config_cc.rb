MRuby::Build.new do |conf|
  toolchain :gcc
end

MRuby::Build.new('gcc') do |conf|
  toolchain :gcc
  conf.gembox 'default'
end

MRuby::Build.new('clang') do |conf|
  toolchain :clang
  conf.gembox 'default'
end
