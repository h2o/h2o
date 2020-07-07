MRuby::Gem::Specification.new('mruby-bin-mruby') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'mruby command'
  spec.bins = %w(mruby)
  spec.add_dependency('mruby-compiler', :core => 'mruby-compiler')
  spec.add_test_dependency('mruby-print', :core => 'mruby-print')

  if build.cxx_exception_enabled?
    build.compile_as_cxx("#{spec.dir}/tools/mruby/mruby.c", "#{spec.build_dir}/tools/mruby/mruby.cxx")
  end
end
