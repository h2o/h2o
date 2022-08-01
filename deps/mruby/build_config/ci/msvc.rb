STDOUT.sync = STDERR.sync = true unless Rake.application.options.always_multitask

def setup_option(conf)
  conf.cc.compile_options.sub!(%r{/Zi }, "") unless ENV['CFLAGS']
  conf.cxx.compile_options.sub!(%r{/Zi }, "") unless ENV['CFLAGS'] || ENV['CXXFLAGS']
  conf.linker.flags << "/DEBUG:NONE" unless ENV['LDFLAGS']
end

MRuby::Build.new do |conf|
  conf.toolchain :visualcpp

  # include all core GEMs
  conf.gembox 'full-core'
  conf.compilers.each do |c|
    c.defines += %w(MRB_GC_FIXED_ARENA)
  end
  setup_option(conf)
  conf.enable_bintest
  conf.enable_test
end
