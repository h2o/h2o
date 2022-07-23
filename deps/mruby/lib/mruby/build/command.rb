require 'forwardable'

module MRuby
  class Command
    include Rake::DSL
    extend Forwardable
    def_delegators :@build, :filename, :objfile, :libfile, :exefile
    attr_accessor :build, :command

    def initialize(build)
      @build = build
    end

    # clone is deep clone without @build
    def clone
      target = super
      excepts = %w(@build)
      instance_variables.each do |attr|
        unless excepts.include?(attr.to_s)
          val = Marshal::load(Marshal.dump(instance_variable_get(attr))) # deep clone
          target.instance_variable_set(attr, val)
        end
      end
      target
    end

    def shellquote(s)
      if ENV['OS'] == 'Windows_NT'
        "\"#{s}\""
      else
        "#{s}"
      end
    end

    private
    def _run(options, params={})
      sh "#{build.filename(command)} #{options % params}"
    end
  end

  class Command::Compiler < Command
    attr_accessor :label, :flags, :include_paths, :defines, :source_exts
    attr_accessor :compile_options, :option_define, :option_include_path, :out_ext
    attr_accessor :cxx_compile_flag, :cxx_exception_flag, :cxx_invalid_flags
    attr_writer :preprocess_options

    def initialize(build, source_exts=[], label: "CC")
      super(build)
      @command = ENV['CC'] || 'cc'
      @label = label
      @flags = [ENV['CFLAGS'] || []]
      @source_exts = source_exts
      @include_paths = ["#{MRUBY_ROOT}/include"]
      @defines = []
      @option_include_path = %q[-I"%s"]
      @option_define = %q[-D"%s"]
      @compile_options = %q[%{flags} -o "%{outfile}" -c "%{infile}"]
      @cxx_invalid_flags = []
      @out_ext = build.exts.object
    end

    alias header_search_paths include_paths

    def preprocess_options
      @preprocess_options ||= @compile_options.sub(/(?:\A|\s)\K-c(?=\s)/, "-E -P")
    end

    def search_header_path(name)
      header_search_paths.find do |v|
        File.exist? build.filename("#{v}/#{name}").sub(/^"(.*)"$/, '\1')
      end
    end

    def search_header(name)
      path = search_header_path name
      path && build.filename("#{path}/#{name}").sub(/^"(.*)"$/, '\1')
    end

    def all_flags(_defines=[], _include_paths=[], _flags=[])
      define_flags = [defines, _defines, build.defines].flatten.map{ |d| option_define % d }
      include_path_flags = [include_paths, _include_paths].flatten.map do |f|
        option_include_path % filename(f)
      end
      [flags, define_flags, include_path_flags, _flags].flatten.join(' ')
    end

    def run(outfile, infile, _defines=[], _include_paths=[], _flags=[])
      mkdir_p File.dirname(outfile)
      flags = all_flags(_defines, _include_paths, _flags)
      if object_ext?(outfile)
        label = @label
        opts = compile_options
      else
        label = "CPP"
        opts = preprocess_options
        flags << " -DMRB_PRESYM_SCANNING"
      end
      _pp label, infile.relative_path, outfile.relative_path
      _run opts, flags: flags, infile: filename(infile), outfile: filename(outfile)
    end

    def define_rules(build_dir, source_dir='', out_ext=build.exts.object)
      gemrake = File.join(source_dir, "mrbgem.rake")
      rakedep = File.exist?(gemrake) ? [ gemrake ] : []

      if build_dir.include? "mrbgems/"
        generated_file_matcher = Regexp.new("^#{Regexp.escape build_dir}/(?!mrbc/)(.*)#{Regexp.escape out_ext}$")
      else
        generated_file_matcher = Regexp.new("^#{Regexp.escape build_dir}/(?!mrbc/|mrbgems/.+/)(.*)#{Regexp.escape out_ext}$")
      end
      source_exts.each do |ext, compile|
        rule generated_file_matcher => [
          proc { |file|
            file.sub(generated_file_matcher, "#{source_dir}/\\1#{ext}")
          },
          proc { |file|
            get_dependencies(file) + rakedep
          }
        ] do |t|
          run t.name, t.prerequisites.first
        end

        rule generated_file_matcher => [
          proc { |file|
            file.sub(generated_file_matcher, "#{build_dir}/\\1#{ext}")
          },
          proc { |file|
            get_dependencies(file) + rakedep
          }
        ] do |t|
          run t.name, t.prerequisites.first
        end
      end
    end

    private

    #
    # === Example of +.d+ file
    #
    # ==== Without <tt>-MP</tt> compiler flag
    #
    #   /build/host/src/array.o: /src/array.c \
    #     /include/mruby/common.h /include/mruby/value.h \
    #     /src/value_array.h
    #
    # ==== With <tt>-MP</tt> compiler flag
    #
    #   /build/host/src/array.o: /src/array.c \
    #     /include/mruby/common.h /include/mruby/value.h \
    #     /src/value_array.h
    #
    #   /include/mruby/common.h:
    #
    #   /include/mruby/value.h:
    #
    #   /src/value_array.h:
    #
    def get_dependencies(file)
      dep_file = file.ext(".d")
      return [MRUBY_CONFIG] unless object_ext?(file) && File.exist?(dep_file)

      deps = File.read(dep_file).gsub("\\\n ", "").split("\n").map do |dep_line|
        # dep_line:
        # - "/build/host/src/array.o:   /src/array.c   /include/mruby/common.h ..."
        # - ""
        # - "/include/mruby/common.h:"
        dep_line.scan(/^\S+:\s+(.+)$/).flatten.map { |s| s.split(' ') }.flatten
        # => ["/src/array.c", "/include/mruby/common.h" , ...]
        #    []
        #    []
      end.flatten.uniq
      deps << MRUBY_CONFIG
    end

    def object_ext?(path)
      File.extname(path) == build.exts.object
    end
  end

  class Command::Linker < Command
    attr_accessor :flags, :library_paths, :flags_before_libraries, :libraries, :flags_after_libraries
    attr_accessor :link_options, :option_library, :option_library_path

    def initialize(build)
      super
      @command = ENV['LD'] || 'ld'
      @flags = (ENV['LDFLAGS'] || [])
      @flags_before_libraries, @flags_after_libraries = [], []
      @libraries = []
      @library_paths = []
      @option_library = %q[-l"%s"]
      @option_library_path = %q[-L"%s"]
      @link_options = %Q[%{flags} -o "%{outfile}" %{objs} %{flags_before_libraries} %{libs} %{flags_after_libraries}]
    end

    def all_flags(_library_paths=[], _flags=[])
      library_path_flags = [library_paths, _library_paths].flatten.map do |f|
        option_library_path % filename(f)
      end
      [flags, library_path_flags, _flags].flatten.join(' ')
    end

    def library_flags(_libraries)
      [libraries, _libraries].flatten.map{ |d| option_library % d }.join(' ')
    end

    def run_attrs
      [@libraries, @library_paths, @flags, @flags_before_libraries, @flags_after_libraries]
    end

    def run(outfile, objfiles, _libraries=[], _library_paths=[], _flags=[], _flags_before_libraries=[], _flags_after_libraries=[])
      mkdir_p File.dirname(outfile)
      library_flags = [libraries, _libraries].flatten.map { |d| option_library % d }

      _pp "LD", outfile.relative_path
      _run link_options, { :flags => all_flags(_library_paths, _flags),
                            :outfile => filename(outfile) , :objs => filename(objfiles).map{|f| %Q["#{f}"]}.join(' '),
                            :flags_before_libraries => [flags_before_libraries, _flags_before_libraries].flatten.join(' '),
                            :flags_after_libraries => [flags_after_libraries, _flags_after_libraries].flatten.join(' '),
                            :libs => library_flags.join(' ') }
    end
  end

  class Command::Archiver < Command
    attr_accessor :archive_options

    def initialize(build)
      super
      @command = ENV['AR'] || 'ar'
      @archive_options = 'rs "%{outfile}" %{objs}'
    end

    def run(outfile, objfiles)
      mkdir_p File.dirname(outfile)
      _pp "AR", outfile.relative_path
      _run archive_options, { :outfile => filename(outfile), :objs => filename(objfiles).map{|f| %Q["#{f}"]}.join(' ') }
    end
  end

  class Command::Yacc < Command
    attr_accessor :compile_options

    def initialize(build)
      super
      @command = 'bison'
      @compile_options = %q[-o "%{outfile}" "%{infile}"]
    end

    def run(outfile, infile)
      mkdir_p File.dirname(outfile)
      _pp "YACC", infile.relative_path, outfile.relative_path
      _run compile_options, { :outfile => filename(outfile) , :infile => filename(infile) }
    end
  end

  class Command::Gperf < Command
    attr_accessor :compile_options

    def initialize(build)
      super
      @command = 'gperf'
      @compile_options = %q[-L ANSI-C -C -p -j1 -i 1 -g -o -t -N mrb_reserved_word -k"1,3,$" "%{infile}" > "%{outfile}"]
    end

    def run(outfile, infile)
      mkdir_p File.dirname(outfile)
      _pp "GPERF", infile.relative_path, outfile.relative_path
      _run compile_options, { :outfile => filename(outfile) , :infile => filename(infile) }
    end
  end

  class Command::Git < Command
    attr_accessor :flags
    attr_accessor :clone_options, :pull_options, :checkout_options, :checkout_detach_options, :reset_options

    def initialize(build)
      super
      @command = 'git'
      @flags = []
      @clone_options = "clone %{flags} %{url} %{dir}"
      @pull_options = "--git-dir %{repo_dir}/.git --work-tree %{repo_dir} pull"
      @checkout_options = "--git-dir %{repo_dir}/.git --work-tree %{repo_dir} checkout %{checksum_hash}"
      @checkout_detach_options = "--git-dir %{repo_dir}/.git --work-tree %{repo_dir} checkout --detach %{checksum_hash}"
      @reset_options = "--git-dir %{repo_dir}/.git --work-tree %{repo_dir} reset %{checksum_hash}"
    end

    def run_clone(dir, url, _flags = [])
      _pp "GIT", url, dir.relative_path
      _run clone_options, { :flags => [flags, _flags].flatten.join(' '), :url => shellquote(url), :dir => shellquote(filename(dir)) }
    end

    def run_pull(dir, url)
      _pp "GIT PULL", url, dir.relative_path
      _run pull_options, { :repo_dir => shellquote(dir) }
    end

    def run_checkout(dir, checksum_hash)
      _pp "GIT CHECKOUT", dir, checksum_hash
      _run checkout_options, { :checksum_hash => checksum_hash, :repo_dir => shellquote(dir) }
    end

    def run_checkout_detach(dir, checksum_hash)
      _pp "GIT CHECKOUT DETACH", dir, checksum_hash
      _run checkout_detach_options, { :checksum_hash => checksum_hash, :repo_dir => shellquote(dir) }
    end

    def run_reset_hard(dir, checksum_hash)
      _pp "GIT RESET", dir, checksum_hash
      _run reset_options, { :checksum_hash => checksum_hash, :repo_dir => shellquote(dir) }
    end

    def commit_hash(dir)
      `#{@command} --git-dir #{shellquote(dir +'/.git')} --work-tree #{shellquote(dir)} rev-parse --verify HEAD`.strip
    end

    def current_branch(dir)
      `#{@command} --git-dir #{shellquote(dir + '/.git')} --work-tree #{shellquote(dir)} rev-parse --abbrev-ref HEAD`.strip
    end
  end

  class Command::Mrbc < Command
    attr_accessor :compile_options

    def initialize(build)
      super
      @command = nil
      @compile_options = "-B%{funcname} -o-"
    end

    def run(out, infiles, funcname, cdump: true, static: false)
      @command ||= @build.mrbcfile
      infiles = [infiles].flatten
      infiles.each_with_index do |f, i|
        _pp i == 0 ? "MRBC" : "", f.relative_path, indent: 2
      end
      opt = @compile_options % {funcname: funcname}
      opt << " -S" if cdump
      opt << " -s" if static
      cmd = %["#{filename @command}" #{opt} #{filename(infiles).map{|f| %["#{f}"]}.join(' ')}]
      puts cmd if Rake.verbose
      IO.popen(cmd, 'r+') do |io|
        out.puts io.read
      end
      # if mrbc execution fail, drop the file
      unless $?.success?
        rm_f out.path
        fail "Command failed with status (#{$?.exitstatus}): [#{cmd[0,42]}...]"
      end
    end
  end

  class Command::CrossTestRunner < Command
    attr_accessor :runner_options
    attr_accessor :verbose_flag
    attr_accessor :flags

    def initialize(build)
      super
      @command = nil
      @runner_options = '%{flags} %{infile}'
      @verbose_flag = ''
      @flags = []
    end

    def emulator
      return "" unless @command
      return [@command, *@flags].map{|c| shellquote(c)}.join(' ')
    end

    def run(testbinfile)
      puts "TEST for " + @build.name
      _run runner_options, { :flags => [flags, verbose_flag].flatten.join(' '), :infile => testbinfile }
    end
  end

end
