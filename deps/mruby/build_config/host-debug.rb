MRuby::Build.new('host') do |conf|
  # load specific toolchain settings
  conf.toolchain

  conf.enable_debug

  # include the default GEMs
  conf.gembox 'full-core'

  # C compiler settings
  conf.cc.defines = %w(MRB_USE_DEBUG_HOOK MRB_NO_BOXING)

  # Generate mruby debugger command (require mruby-eval)
  conf.gem :core => "mruby-bin-debugger"

  # test
  conf.enable_test
  # bintest
  conf.enable_bintest
end
