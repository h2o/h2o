MRuby.each_target do
  file libfile("#{build_dir}/lib/libmruby") => libmruby.flatten do |t|
    archiver.run t.name, t.prerequisites
  end

  file "#{build_dir}/lib/libmruby.flags.mak" => [__FILE__, libfile("#{build_dir}/lib/libmruby")] do |t|
    open(t.name, 'w') do |f|
      f.puts "MRUBY_CFLAGS = #{cc.all_flags}"

      gem_flags = gems.map { |g| g.linker.flags }
      gem_library_paths = gems.map { |g| g.linker.library_paths }
      f.puts "MRUBY_LDFLAGS = #{linker.all_flags(gem_library_paths, gem_flags)} #{linker.option_library_path % "#{build_dir}/lib"}"

      gem_flags_before_libraries = gems.map { |g| g.linker.flags_before_libraries }
      f.puts "MRUBY_LDFLAGS_BEFORE_LIBS = #{[linker.flags_before_libraries, gem_flags_before_libraries].flatten.join(' ')}"

      gem_libraries = gems.map { |g| g.linker.libraries }
      f.puts "MRUBY_LIBS = #{linker.option_library % 'mruby'} #{linker.library_flags(gem_libraries)}"

      f.puts "MRUBY_LIBMRUBY_PATH = #{libfile("#{build_dir}/lib/libmruby")}"
    end
  end
  task :all => "#{build_dir}/lib/libmruby.flags.mak"
end
