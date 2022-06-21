MRuby::Gem::Specification.new('mruby-test') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby test'

  spec.test_rbfiles = Dir.glob("#{MRUBY_ROOT}/test/t/*.rb")

  clib = "#{build_dir}/mrbtest.c"
  mlib = clib.ext(exts.object)
  exec = exefile("#{build.build_dir}/bin/mrbtest")
  assert_c = "#{build_dir}/assert.c"
  assert_rb = "#{MRUBY_ROOT}/test/assert.rb"
  assert_lib = assert_c.ext(exts.object)
  mrbtest_lib = libfile("#{build_dir}/mrbtest")
  mrbtest_objs = [assert_lib]
  driver_objs = srcs_to_objs(".")

  file assert_lib => assert_c
  file assert_c => [assert_rb, build.mrbcfile] do |t|
    _pp "GEN", t.name.relative_path
    mkdir_p File.dirname(t.name)
    open(t.name, 'w') do |f|
      mrbc.run f, assert_rb, 'mrbtest_assert_irep', cdump: false
    end
  end

  gem_table = build.gems.generate_gem_table build

  build.gems.each do |g|
    test_rbobj = g.test_rbireps.ext(exts.object)
    mrbtest_objs.concat(g.test_objs)
    mrbtest_objs << test_rbobj
    dep_list = build.gems.tsort_dependencies([g.name], gem_table).select(&:generate_functions)

    file test_rbobj => g.test_rbireps
    file g.test_rbireps => [g.test_rbfiles, build.mrbcfile].flatten do |t|
      _pp "GEN", t.name.relative_path
      mkdir_p File.dirname(t.name)
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
          g.build.mrbc.run f, test_preload, "gem_test_irep_#{g.funcname}_preload", cdump: false
        end
        g.test_rbfiles.flatten.each_with_index do |rbfile, i|
          g.build.mrbc.run f, rbfile, "gem_test_irep_#{g.funcname}_#{i}", cdump: false, static: true
        end
        f.puts %Q[void mrb_#{g.funcname}_gem_test(mrb_state *mrb);] if g.custom_test_init?
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
            f.puts %Q[    fprintf(stderr, "Invalid mrb_state, exiting \%s", __func__);]
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
            f.puts %Q[    mrb_close(mrb2);]
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

  file mrbtest_lib => mrbtest_objs do |t|
    build.archiver.run t.name, t.prerequisites
  end

  unless build.build_mrbtest_lib_only?
    file exec => [*driver_objs, mlib, mrbtest_lib, build.libmruby_static] do |t|
      build.linker.run t.name, t.prerequisites, *build.gems.linker_attrs
    end
  end

  file mlib => clib
  file clib => ["#{build.build_dir}/mrbgems/active_gems.txt", build.mrbcfile, __FILE__] do |_t|
    _pp "GEN", clib.relative_path
    mkdir_p File.dirname(clib)
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
      f.puts %Q[struct mrb_state;]
      f.puts %Q[typedef struct mrb_state mrb_state;]
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
