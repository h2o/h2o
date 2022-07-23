MRuby::Toolchain.new(:visualcpp) do |conf, _params|
  compiler_flags = %w(/nologo /W3 /MD /O2 /D_CRT_SECURE_NO_WARNINGS)
  [conf.cc, conf.cxx].each do |compiler|
    if compiler == conf.cc
      compiler.command = ENV['CC'] || 'cl.exe'
      # C4013: implicit function declaration
      compiler.flags = [*(ENV['CFLAGS'] || compiler_flags + %w(/we4013))]
    else
      compiler.command = ENV['CXX'] || 'cl.exe'
      compiler.flags = [*(ENV['CXXFLAGS'] || ENV['CFLAGS'] || compiler_flags + %w(/EHs))]
    end
    compiler.defines = %w(MRB_STACK_EXTEND_DOUBLING)
    compiler.option_include_path = %q[/I"%s"]
    compiler.option_define = '/D%s'
    compiler.compile_options = %Q[/Zi /c /Fo"%{outfile}" %{flags} "%{infile}"]
    compiler.preprocess_options = %Q[/EP %{flags} "%{infile}" > "%{outfile}"]
    compiler.cxx_compile_flag = '/TP'
    compiler.cxx_exception_flag = '/EHs'
  end

  conf.linker do |linker|
    linker.command = ENV['LD'] || 'link.exe'
    linker.flags = [ENV['LDFLAGS'] || %w(/NOLOGO /DEBUG /INCREMENTAL:NO /OPT:ICF /OPT:REF)]
    linker.libraries = %w()
    linker.library_paths = %w()
    linker.option_library = '%s.lib'
    linker.option_library_path = '/LIBPATH:%s'
    linker.link_options = %Q[%{flags} /OUT:"%{outfile}" %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}]
  end

  conf.archiver do |archiver|
    archiver.command = ENV['AR'] || 'lib.exe'
    archiver.archive_options = '/nologo /OUT:"%{outfile}" %{objs}'
  end

  conf.yacc do |yacc|
    yacc.command = ENV['YACC'] || 'bison.exe'
    yacc.compile_options = %q[-o "%{outfile}" "%{infile}"]
  end

  conf.gperf do |gperf|
    gperf.command = 'gperf.exe'
    gperf.compile_options = %q[-L ANSI-C -C -p -j1 -i 1 -g -o -t -N mrb_reserved_word -k"1,3,$" "%{infile}" > "%{outfile}"]
  end

  conf.exts do |exts|
    exts.object = '.obj'
    exts.executable = '.exe'
    exts.library = '.lib'
  end

  conf.file_separator = '\\'
end
