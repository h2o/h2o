MRuby.each_target do
  current_dir = File.dirname(__FILE__).relative_path_from(Dir.pwd)
  relative_from_root = File.dirname(__FILE__).relative_path_from(MRUBY_ROOT)
  current_build_dir = "#{build_dir}/#{relative_from_root}"

  exec = exefile("#{current_build_dir}/mrbtest")
  clib = "#{current_build_dir}/mrbtest.c"
  mlib = clib.ext(exts.object)
  mrbs = Dir.glob("#{current_dir}/t/*.rb")
  init = "#{current_dir}/init_mrbtest.c"
  ass_c = "#{current_build_dir}/assert.c"
  ass_lib = ass_c.ext(exts.object)

  mrbtest_lib = libfile("#{current_build_dir}/mrbtest")
  mrbtest_objs = [mlib, ass_lib]
  gems.each do |v|
    mrbtest_objs.concat v.test_objs
  end
  file mrbtest_lib => mrbtest_objs do |t|
    archiver.run t.name, t.prerequisites
  end

  unless build_mrbtest_lib_only?
    driver_obj = objfile("#{current_build_dir}/driver")
    file exec => [driver_obj, mrbtest_lib, libfile("#{build_dir}/lib/libmruby")] do |t|
      gem_flags = gems.map { |g| g.linker.flags }
      gem_flags_before_libraries = gems.map { |g| g.linker.flags_before_libraries }
      gem_flags_after_libraries = gems.map { |g| g.linker.flags_after_libraries }
      gem_libraries = gems.map { |g| g.linker.libraries }
      gem_library_paths = gems.map { |g| g.linker.library_paths }
      linker.run t.name, t.prerequisites, gem_libraries, gem_library_paths, gem_flags, gem_flags_before_libraries
    end
  end

  file ass_lib => ass_c
  file ass_c => ["#{current_dir}/assert.rb", __FILE__] do |t|
    FileUtils.mkdir_p File.dirname t.name
    open(t.name, 'w') do |f|
      mrbc.run f, [t.prerequisites.first], 'mrbtest_assert_irep'
    end
  end

  file mlib => clib
  file clib => [mrbcfile, init, __FILE__] + mrbs do |t|
    _pp "GEN", "*.rb", "#{clib.relative_path}"
    FileUtils.mkdir_p File.dirname(clib)
    open(clib, 'w') do |f|
      f.puts %Q[/*]
      f.puts %Q[ * This file contains a list of all]
      f.puts %Q[ * test functions.]
      f.puts %Q[ *]
      f.puts %Q[ * IMPORTANT:]
      f.puts %Q[ *   This file was generated!]
      f.puts %Q[ *   All manual changes will get lost.]
      f.puts %Q[ */]
      f.puts %Q[]
      f.puts IO.read(init)
      mrbc.run f, mrbs, 'mrbtest_irep'
      gems.each do |g|
        f.puts %Q[void GENERATED_TMP_mrb_#{g.funcname}_gem_test(mrb_state *mrb);]
      end
      f.puts %Q[void mrbgemtest_init(mrb_state* mrb) {]
      gems.each do |g|
        f.puts %Q[    GENERATED_TMP_mrb_#{g.funcname}_gem_test(mrb);]
      end
      f.puts %Q[}]
    end
  end
end
