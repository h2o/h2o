MRuby::Gem::Specification.new 'mruby-bin-mrbc' do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby compiler executable'

  spec.add_dependency 'mruby-compiler', :core => 'mruby-compiler'

  exec = exefile("#{build.build_dir}/bin/mrbc")
  mrbc_objs = Dir.glob("#{spec.dir}/tools/mrbc/*.c").map { |f| objfile(f.pathmap("#{spec.build_dir}/tools/mrbc/%n")) }.flatten

  file exec => mrbc_objs + [build.libmruby_core_static] do |t|
    build.linker.run t.name, t.prerequisites
  end

  build.bins << 'mrbc' unless build.bins.find { |v| v == 'mrbc' }
end
