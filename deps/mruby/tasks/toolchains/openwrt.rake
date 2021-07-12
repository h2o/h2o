# usage of environmental variables to set the
# cross compiling toolchain proper
MRuby::Toolchain.new(:openwrt) do |conf|
  [conf.cc, conf.objc, conf.asm].each do |cc|
    cc.command = ENV['TARGET_CC']
    cc.flags = ENV['TARGET_CFLAGS']
    cc.include_paths = ["#{MRUBY_ROOT}/include"]
    cc.option_include_path = %q[-I"%s"]
    cc.option_define = '-D%s'
    cc.compile_options = %q[%{flags} -MMD -o "%{outfile}" -c "%{infile}"]
  end

  [conf.cxx].each do |cxx|
    cxx.command = ENV['TARGET_CXX']
    cxx.flags = ENV['TARGET_CXXFLAGS']
    cxx.include_paths = ["#{MRUBY_ROOT}/include"]
    cxx.option_include_path = %q[-I"%s"]
    cxx.option_define = '-D%s'
    cxx.compile_options = %q[%{flags} -MMD -o "%{outfile}" -c "%{infile}"]
   end

  conf.linker do |linker|
    linker.command = ENV['TARGET_CC']
    linker.flags = ENV['TARGET_LDFLAGS']
    linker.libraries = %w(m)
    linker.library_paths = []
    linker.option_library = '-l%s'
    linker.option_library_path = '-L%s'
    linker.link_options = '%{flags} -o "%{outfile}" %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}'
  end

  conf.archiver do |archiver|
    archiver.command = ENV['TARGET_AR']
    archiver.archive_options = 'rs "%{outfile}" %{objs}'
  end
end
