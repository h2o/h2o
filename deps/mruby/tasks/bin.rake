MRuby.each_target do |build|
  if build.host? && build.mrbc_build && !build.gems["mruby-bin-mrbc"]
    exe = build.exefile("#{build.mrbc_build.build_dir}/bin/mrbc")
    build.products << build.define_installer(exe)
  end

  build.bins.each{|bin| build.products << define_installer_if_needed(bin)}

  build.gems.each do |gem|
    linker_attrs = build.gems.linker_attrs(gem)
    gem.bins.each do |bin|
      exe = build.exefile("#{build.build_dir}/bin/#{bin}")
      objs = Dir["#{gem.dir}/tools/#{bin}/*.{c,cpp,cxx,cc}"].map do |f|
        build.objfile(f.pathmap("#{gem.build_dir}/tools/#{bin}/%n"))
      end
      file exe => objs.concat(build.libraries) do |t|
        build.linker.run t.name, t.prerequisites, *linker_attrs
      end

      build.products << define_installer_if_needed(bin)
    end
  end
end
