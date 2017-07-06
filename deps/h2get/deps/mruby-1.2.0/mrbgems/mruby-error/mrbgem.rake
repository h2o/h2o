MRuby::Gem::Specification.new('mruby-error') do |spec|
  spec.license = 'MIT'
  spec.author  = 'mruby developers'
  spec.summary = 'extensional error handling'

  if build.cxx_abi_enabled?
    @objs << build.compile_as_cxx("#{spec.dir}/src/exception.c", "#{spec.build_dir}/src/exception.cxx")
    @objs.delete_if { |v| v == objfile("#{spec.build_dir}/src/exception") }
  end
end
