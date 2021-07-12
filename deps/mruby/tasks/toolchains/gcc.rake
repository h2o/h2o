MRuby::Toolchain.new(:gcc) do |conf, params|
  default_command = params[:default_command] || 'gcc'
  compiler_flags = %w(-g -O3 -Wall -Wundef)
  c_mandatory_flags = %w(-std=gnu99)
  cxx_invalid_flags = %w(-Wdeclaration-after-statement -Werror-implicit-function-declaration)

  [conf.cc, conf.objc, conf.asm, conf.cxx].each do |compiler|
    if compiler == conf.cxx
      compiler.command = ENV['CXX'] || default_command.sub(/cc|$/, '++')
      compiler.flags = [ENV['CXXFLAGS'] || ENV['CFLAGS'] || compiler_flags]
    else
      compiler.command = ENV['CC'] || default_command
      compiler.flags = [c_mandatory_flags, ENV['CFLAGS'] || [compiler_flags, cxx_invalid_flags, %w(-Wwrite-strings)]]
    end
    compiler.option_include_path = %q[-I"%s"]
    compiler.option_define = '-D%s'
    compiler.compile_options = %q[%{flags} -MMD -o "%{outfile}" -c "%{infile}"]
    compiler.cxx_compile_flag = '-x c++ -std=gnu++03'
    compiler.cxx_exception_flag = '-fexceptions'
    compiler.cxx_invalid_flags = c_mandatory_flags + cxx_invalid_flags
  end

  conf.linker do |linker|
    linker.command = ENV['LD'] || ENV['CXX'] || ENV['CC'] || default_command
    linker.flags = [ENV['LDFLAGS'] || %w()]
    linker.libraries = %w(m)
    linker.library_paths = []
    linker.option_library = '-l%s'
    linker.option_library_path = '-L%s'
    linker.link_options = '%{flags} -o "%{outfile}" %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}'
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

  def conf.enable_sanitizer(*opts)
    fail 'sanitizer already set' if @sanitizer_list

    @sanitizer_list = opts
    flg = "-fsanitize=#{opts.join ','}"
    [self.cc, self.cxx, self.linker].each{|cmd| cmd.flags << flg }
  end
end
