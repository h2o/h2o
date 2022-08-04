MRuby.each_target do
  file libmruby_core_static => libmruby_core_objs.flatten do |t|
    archiver.run t.name, t.prerequisites
  end

  products << libmruby_core_static

  next unless libmruby_enabled?

  file libmruby_static => libmruby_objs.flatten do |t|
    archiver.run t.name, t.prerequisites
  end

  file "#{build_dir}/lib/libmruby.flags.mak" => [__FILE__, libmruby_static] do |t|
    mkdir_p File.dirname t.name
    open(t.name, 'w') do |f|
      gemincs = gems.map { |g| g.export_include_paths.map { |n| g.filename(n) } }.flatten.uniq
      f.puts "MRUBY_CFLAGS = #{cc.all_flags([], gemincs)}"

      f.puts "MRUBY_CC = #{cc.command}"
      f.puts "MRUBY_LD = #{linker.command}"

      libgems = gems.reject{|g| g.bin?}
      gem_flags = libgems.map {|g| g.linker.flags }
      gem_library_paths = libgems.map {|g| g.linker.library_paths }
      f.puts "MRUBY_LDFLAGS = #{linker.all_flags(gem_library_paths, gem_flags)} #{linker.option_library_path % "#{build_dir}/lib"}"

      gem_flags_before_libraries = libgems.map {|g| g.linker.flags_before_libraries }
      f.puts "MRUBY_LDFLAGS_BEFORE_LIBS = #{[linker.flags_before_libraries, gem_flags_before_libraries].flatten.join(' ')}"

      gem_libraries = libgems.map {|g| g.linker.libraries }
      f.puts "MRUBY_LIBS = #{linker.option_library % 'mruby'} #{linker.library_flags(gem_libraries)}"

      f.puts "MRUBY_LIBMRUBY_PATH = #{libmruby_static}"
    end
  end

  products << libmruby_static
end
