# usage of environmental variables to set the
# cross compiling toolchain proper
MRuby::Toolchain.new(:openwrt) do |conf|
  [conf.cc, conf.cxx, conf.objc, conf.asm].each do |cc|
    if cc == conf.cxx
      cc.command = ENV['TARGET_CXX']
      cc.flags = ENV['TARGET_CXXFLAGS']
    else
      cc.command = ENV['TARGET_CC']
      cc.flags = ENV['TARGET_CFLAGS']
    end
    cc.option_include_path = %q[-I"%s"]
    cc.option_define = '-D%s'
    cc.compile_options = '%{flags} -MMD -o "%{outfile}" -c "%{infile}"'
    cc.preprocess_options = '%{flags} -o "%{outfile}" -E -P "%{infile}"'
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
