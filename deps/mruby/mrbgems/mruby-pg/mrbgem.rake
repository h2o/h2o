MRuby::Gem::Specification.new('mruby-pg') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Narihiro Nakamura'
  spec.summary = 'postgresql mruby binding'

  # for debug
  # spec.cc.flags = ["-g3", "-std=gnu99", "-O0", "-Wall", "-Werror-implicit-function-declaration", "-Wdeclaration-after-statement"]

  spec.cc.include_paths << `pg_config --includedir`.chomp
  spec.linker.libraries << 'pq'
end
