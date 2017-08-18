MRuby::Gem::Specification.new('mruby-test') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby test'

  build.bins << 'mrbtest'
  spec.add_dependency('mruby-compiler', :core => 'mruby-compiler')

  spec.test_rbfiles = Dir.glob("#{MRUBY_ROOT}/test/t/*.rb")

  clib = "#{build_dir}/mrbtest.c"
  mlib = clib.ext(exts.object)
  exec = exefile("#{build.build_dir}/bin/mrbtest")

  libmruby = libfile("#{build.build_dir}/lib/libmruby")
  libmruby_core = libfile("#{build.build_dir}/lib/libmruby_core")

  mrbtest_lib = libfile("#{build_dir}/mrbtest")
  mrbtest_objs = []

  driver_obj = objfile("#{build_dir}/driver")
  driver = "#{spec.dir}/driver.c"

  assert_c = "#{build_dir}/assert.c"
  assert_rb = "#{MRUBY_ROOT}/test/assert.rb"
  assert_lib = assert_c.ext(exts.object)
  mrbtest_objs << assert_lib

  file assert_lib => assert_c
  file assert_c => assert_rb do |t|
    open(t.name, 'w') do |f|
      mrbc.run f, assert_rb, 'mrbtest_assert_irep'
    end
  end

  gem_table = build.gems.generate_gem_table build

  build.gems.each do |g|
    test_rbobj = g.test_rbireps.ext(exts.object)
    g.test_objs << test_rbobj
    dep_list = build.gems.tsort_dependencies(g.test_dependencies, gem_table).select(&:generate_functions)

    file test_rbobj => g.test_rbireps
    file g.test_rbireps => [g.test_rbfiles].flatten do |t|
      FileUtils.mkdir_p File.dirname(t.name)
      open(t.name, 'w') do |f|
        g.print_gem_test_header(f)
        test_preload = g.test_preload and [g.dir, MRUBY_ROOT].map {|dir|
          File.expand_path(g.test_preload, dir)
        }.find {|file| File.exist?(file) }

        f.puts %Q[/*]
        f.puts %Q[ * This file contains a test code for #{g.name} gem.]
        f.puts %Q[ *]
        f.puts %Q[ * IMPORTANT:]
        f.puts %Q[ *   This file was generated!]
        f.puts %Q[ *   All manual changes will get lost.]
        f.puts %Q[ */]
        if test_preload.nil?
          f.puts %Q[extern const uint8_t mrbtest_assert_irep[];]
        else
          g.build.mrbc.run f, test_preload, "gem_test_irep_#{g.funcname}_preload"
        end
        g.test_rbfiles.flatten.each_with_index do |rbfile, i|
          g.build.mrbc.run f, rbfile, "gem_test_irep_#{g.funcname}_#{i}"
        end
        f.puts %Q[void mrb_#{g.funcname}_gem_test(mrb_state *mrb);] unless g.test_objs.empty?
        dep_list.each do |d|
          f.puts %Q[void GENERATED_TMP_mrb_#{d.funcname}_gem_init(mrb_state *mrb);]
          f.puts %Q[void GENERATED_TMP_mrb_#{d.funcname}_gem_final(mrb_state *mrb);]
        end
        f.puts %Q[void mrb_init_test_driver(mrb_state *mrb, mrb_bool verbose);]
        f.puts %Q[void mrb_t_pass_result(mrb_state *dst, mrb_state *src);]
        f.puts %Q[void GENERATED_TMP_mrb_#{g.funcname}_gem_test(mrb_state *mrb) {]
        unless g.test_rbfiles.empty?
          f.puts %Q[  mrb_state *mrb2;]
          unless g.test_args.empty?
            f.puts %Q[  mrb_value test_args_hash;]
          end
          f.puts %Q[  int ai;]
          g.test_rbfiles.count.times do |i|
            f.puts %Q[  ai = mrb_gc_arena_save(mrb);]
            f.puts %Q[  mrb2 = mrb_open_core(mrb_default_allocf, NULL);]
            f.puts %Q[  if (mrb2 == NULL) {]
            f.puts %Q[    fprintf(stderr, "Invalid mrb_state, exiting \%s", __FUNCTION__);]
            f.puts %Q[    exit(EXIT_FAILURE);]
            f.puts %Q[  }]
            dep_list.each do |d|
              f.puts %Q[  GENERATED_TMP_mrb_#{d.funcname}_gem_init(mrb2);]
              f.puts %Q[  mrb_state_atexit(mrb2, GENERATED_TMP_mrb_#{d.funcname}_gem_final);]
            end
            f.puts %Q[  mrb_init_test_driver(mrb2, mrb_test(mrb_gv_get(mrb, mrb_intern_lit(mrb, "$mrbtest_verbose"))));]
            if test_preload.nil?
              f.puts %Q[  mrb_load_irep(mrb2, mrbtest_assert_irep);]
            else
              f.puts %Q[  mrb_load_irep(mrb2, gem_test_irep_#{g.funcname}_preload);]
            end
            f.puts %Q[  if (mrb2->exc) {]
            f.puts %Q[    mrb_print_error(mrb2);]
            f.puts %Q[    exit(EXIT_FAILURE);]
            f.puts %Q[  }]
            f.puts %Q[  mrb_const_set(mrb2, mrb_obj_value(mrb2->object_class), mrb_intern_lit(mrb2, "GEMNAME"), mrb_str_new(mrb2, "#{g.name}", #{g.name.length}));]

            unless g.test_args.empty?
              f.puts %Q[  test_args_hash = mrb_hash_new_capa(mrb, #{g.test_args.length}); ]
              g.test_args.each do |arg_name, arg_value|
                escaped_arg_name = arg_name.gsub('\\', '\\\\\\\\').gsub('"', '\"')
                escaped_arg_value = arg_value.gsub('\\', '\\\\\\\\').gsub('"', '\"')
                f.puts %Q[  mrb_hash_set(mrb2, test_args_hash, mrb_str_new(mrb2, "#{escaped_arg_name.to_s}", #{escaped_arg_name.to_s.length}), mrb_str_new(mrb2, "#{escaped_arg_value.to_s}", #{escaped_arg_value.to_s.length})); ]
              end
              f.puts %Q[  mrb_const_set(mrb2, mrb_obj_value(mrb2->object_class), mrb_intern_lit(mrb2, "TEST_ARGS"), test_args_hash); ]
            end

            f.puts %Q[  mrb_#{g.funcname}_gem_test(mrb2);] if g.custom_test_init?

            f.puts %Q[  mrb_load_irep(mrb2, gem_test_irep_#{g.funcname}_#{i});]
            f.puts %Q[  ]

            f.puts %Q[  mrb_t_pass_result(mrb, mrb2);]
            f.puts %Q[  mrb_close(mrb2);]
            f.puts %Q[  mrb_gc_arena_restore(mrb, ai);]
          end
        end
        f.puts %Q[}]
      end
    end
  end

  build.gems.each do |v|
    mrbtest_objs.concat v.test_objs
  end

  file mrbtest_lib => mrbtest_objs do |t|
    build.archiver.run t.name, t.prerequisites
  end

  unless build.build_mrbtest_lib_only?
    file exec => [driver_obj, mlib, mrbtest_lib, libmruby_core, libmruby] do |t|
      gem_flags = build.gems.map { |g| g.linker.flags }
      gem_flags_before_libraries = build.gems.map { |g| g.linker.flags_before_libraries }
      gem_flags_after_libraries = build.gems.map { |g| g.linker.flags_after_libraries }
      gem_libraries = build.gems.map { |g| g.linker.libraries }
      gem_library_paths = build.gems.map { |g| g.linker.library_paths }
      build.linker.run t.name, t.prerequisites, gem_libraries, gem_library_paths, gem_flags, gem_flags_before_libraries
    end
  end

  init = "#{spec.dir}/init_mrbtest.c"

  # store the last gem selection and make the re-build
  # of the test gem depending on a change to the gem
  # selection
  active_gems = "#{build_dir}/active_gems.lst"
  FileUtils.mkdir_p File.dirname(active_gems)
  open(active_gems, 'w+') do |f|
    build.gems.each do |g|
      f.puts g.name
    end
  end
  file clib => active_gems

  file mlib => clib
  file clib => init do |t|
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
      build.gems.each do |g|
        f.puts %Q[void GENERATED_TMP_mrb_#{g.funcname}_gem_test(mrb_state *mrb);]
      end
      f.puts %Q[void mrbgemtest_init(mrb_state* mrb) {]
      build.gems.each do |g|
        f.puts %Q[    GENERATED_TMP_mrb_#{g.funcname}_gem_test(mrb);]
      end
      f.puts %Q[}]
    end
  end
end
