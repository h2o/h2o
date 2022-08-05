STDOUT.sync = STDERR.sync = true unless Rake.application.options.always_multitask

MRuby::Build.new('full-debug') do |conf|
  conf.toolchain
  conf.enable_debug

  # include all core GEMs
  conf.gembox 'full-core'
  conf.cc.defines += %w(MRB_GC_STRESS MRB_USE_DEBUG_HOOK MRB_UTF8_STRING)

  conf.enable_test
end

MRuby::Build.new do |conf|
  conf.toolchain

  # include all core GEMs
  conf.gembox 'full-core'
  conf.gem :core => 'mruby-bin-debugger'
  conf.compilers.each do |c|
    c.defines += %w(MRB_GC_FIXED_ARENA MRB_UTF8_STRING)
  end
  conf.enable_bintest
  conf.enable_test
end

MRuby::Build.new('cxx_abi') do |conf|
  conf.toolchain

  conf.gembox 'full-core'
  conf.cc.flags += %w(-fpermissive -std=gnu++03)
  conf.compilers.each do |c|
    c.defines += %w(MRB_GC_FIXED_ARENA MRB_UTF8_STRING)
  end
  conf.enable_test

  conf.enable_cxx_abi

  conf.build_mrbc_exec
end
