# Define cross build settings
MRuby::CrossBuild.new('cross-32bit') do |conf|
  conf.toolchain :gcc

  conf.cc.flags << "-m32"
  conf.linker.flags << "-m32"

  # conf.build_mrbtest_lib_only

  conf.gem :core => "mruby-bin-mruby"
  conf.gem "#{MRUBY_ROOT}/examples/mrbgems/c_and_ruby_extension_example"

  conf.test_runner.command = 'env'
end
