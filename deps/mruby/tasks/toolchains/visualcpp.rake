MRuby::Toolchain.new(:visualcpp) do |conf, _params|
  conf.cc do |cc|
    cc.command = ENV['CC'] || 'cl.exe'
    # C4013: implicit function declaration
    cc.flags = [ENV['CFLAGS'] || %w(/c /nologo /W3 /we4013 /Zi /MD /O2 /D_CRT_SECURE_NO_WARNINGS)]
    cc.defines = %w(DISABLE_GEMS MRB_STACK_EXTEND_DOUBLING)
    cc.option_include_path = '/I%s'
    cc.option_define = '/D%s'
    cc.compile_options = "%{flags} /Fo%{outfile} %{infile}"
    cc.cxx_compile_flag = '/TP'
    cc.cxx_exception_flag = '/EHs'
  end

  conf.cxx do |cxx|
    cxx.command = ENV['CXX'] || 'cl.exe'
    cxx.flags = [ENV['CXXFLAGS'] || ENV['CFLAGS'] || %w(/c /nologo /W3 /Zi /MD /O2 /EHs /D_CRT_SECURE_NO_WARNINGS)]
    cxx.defines = %w(DISABLE_GEMS MRB_STACK_EXTEND_DOUBLING)
    cxx.option_include_path = '/I%s'
    cxx.option_define = '/D%s'
    cxx.compile_options = "%{flags} /Fo%{outfile} %{infile}"
    cxx.cxx_compile_flag = '/TP'
    cxx.cxx_exception_flag = '/EHs'
  end

  conf.linker do |linker|
    linker.command = ENV['LD'] || 'link.exe'
    linker.flags = [ENV['LDFLAGS'] || %w(/NOLOGO /DEBUG /INCREMENTAL:NO /OPT:ICF /OPT:REF)]
    linker.libraries = %w()
    linker.library_paths = %w()
    linker.option_library = '%s.lib'
    linker.option_library_path = '/LIBPATH:%s'
    linker.link_options = "%{flags} /OUT:%{outfile} %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}"
  end

  conf.archiver do |archiver|
    archiver.command = ENV['AR'] || 'lib.exe'
    archiver.archive_options = '/nologo /OUT:%{outfile} %{objs}'
  end

  conf.yacc do |yacc|
    yacc.command = ENV['YACC'] || 'bison.exe'
    yacc.compile_options = '-o %{outfile} %{infile}'
  end

  conf.gperf do |gperf|
    gperf.command = 'gperf.exe'
    gperf.compile_options = '-L ANSI-C -C -p -j1 -i 1 -g -o -t -N mrb_reserved_word -k"1,3,$" %{infile} > %{outfile}'
  end

  conf.exts do |exts|
    exts.object = '.obj'
    exts.executable = '.exe'
    exts.library = '.lib'
  end

  conf.file_separator = '\\'

  if require 'open3'
    Open3.popen3 conf.cc.command do |_, _, e, _|
      if /Version (\d{2})\.\d{2}\.\d{5}/ =~ e.gets && $1.to_i <= 17
        m = "# VS2010/2012 support will be dropped after the next release! #"
        h = "#" * m.length
        puts h, m, h
      end
    end
  end

end
