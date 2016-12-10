MRuby::Toolchain.new(:gcc) do |conf, _params|
  [conf.cc, conf.objc, conf.asm].each do |cc|
    cc.command = ENV['CC'] || 'gcc'
    cc.flags = [ENV['CFLAGS'] || %w(-g -std=gnu99 -O3 -Wall -Werror-implicit-function-declaration -Wdeclaration-after-statement -Wwrite-strings)]
    cc.defines = %w(DISABLE_GEMS)
    cc.option_include_path = '-I%s'
    cc.option_define = '-D%s'
    cc.compile_options = '%{flags} -MMD -o %{outfile} -c %{infile}'
    cc.cxx_compile_flag = '-x c++ -std=c++03'
  end

  [conf.cxx].each do |cxx|
    cxx.command = ENV['CXX'] || 'g++'
    cxx.flags = [ENV['CXXFLAGS'] || ENV['CFLAGS'] || %w(-g -O3 -Wall -Werror-implicit-function-declaration)]
    cxx.defines = %w(DISABLE_GEMS)
    cxx.option_include_path = '-I%s'
    cxx.option_define = '-D%s'
    cxx.compile_options = '%{flags} -MMD -o %{outfile} -c %{infile}'
    cxx.cxx_compile_flag = '-x c++ -std=c++03'
  end

  conf.linker do |linker|
    linker.command = ENV['LD'] || 'gcc'
    linker.flags = [ENV['LDFLAGS'] || %w()]
    linker.libraries = %w(m)
    linker.library_paths = []
    linker.option_library = '-l%s'
    linker.option_library_path = '-L%s'
    linker.link_options = '%{flags} -o %{outfile} %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}'
  end

  [[conf.cc, 'c'], [conf.cxx, 'c++']].each do |cc, lang|
    cc.instance_variable_set :@header_search_language, lang
    def cc.header_search_paths
      if @header_search_command != command
        result = `echo | #{build.filename command} -x#{@header_search_language} -Wp,-v - -fsyntax-only 2>&1`
        result = `echo | #{command} -x#{@header_search_language} -Wp,-v - -fsyntax-only 2>&1` if $?.exitstatus != 0
        return include_paths if  $?.exitstatus != 0

        @frameworks = []
        @header_search_paths = result.lines.map { |v|
          framework = v.match(/^ (.*)(?: \(framework directory\))$/)
          if framework
            @frameworks << framework[1]
            next nil
          end

          v.match(/^ (.*)$/)
        }.compact.map { |v| v[1] }.select { |v| File.directory? v }
        @header_search_paths += include_paths
        @header_search_command = command
      end
      @header_search_paths
    end
  end
end
