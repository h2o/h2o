require "mruby/core_ext"
require "mruby/build/load_gems"
require "mruby/build/command"

module MRuby
  autoload :Gem, "mruby/gem"
  autoload :Lockfile, "mruby/lockfile"
  autoload :Presym, "mruby/presym"

  class << self
    def targets
      @targets ||= {}
    end

    def each_target(&block)
      return to_enum(:each_target) if block.nil?
      @targets.each do |key, target|
        target.instance_eval(&block)
      end
    end
  end

  class Toolchain
    class << self
      attr_accessor :toolchains

      def guess
        if cc = ENV["CC"] || ENV["CXX"]
          return "clang" if cc.include?("clang")
        else
          return "clang" if RUBY_PLATFORM =~ /darwin|(?:free|open)bsd/
          return "gcc" if RUBY_PLATFORM.include?("cygwin")
          return "visualcpp" if ENV.include?("VisualStudioVersion")
          return "visualcpp" if ENV.include?("VSINSTALLDIR")
        end
        "gcc"
      end
    end

    def initialize(name, &block)
      @name, @initializer = name.to_s, block
      MRuby::Toolchain.toolchains[@name] = self
    end

    def setup(conf, params={})
      conf.instance_exec(conf, params, &@initializer)
    end

    self.toolchains = {}
  end

  class Build
    class << self
      attr_accessor :current

      def mruby_config_path
        path = ENV['MRUBY_CONFIG'] || ENV['CONFIG']
        if path.nil? || path.empty?
          path = "#{MRUBY_ROOT}/build_config/default.rb"
        elsif !File.file?(path) && !Pathname.new(path).absolute?
          f = "#{MRUBY_ROOT}/build_config/#{path}.rb"
          path = File.exist?(f) ? f : File.extname(path).empty? ? f : path
        end
        path
      end

      def install_dir
        @install_dir ||= ENV['INSTALL_DIR'] || "#{MRUBY_ROOT}/bin"
      end
    end

    include Rake::DSL
    include LoadGems
    attr_accessor :name, :bins, :exts, :file_separator, :build_dir, :gem_clone_dir, :defines
    attr_reader :products, :libmruby_core_objs, :libmruby_objs, :gems, :toolchains, :presym, :mrbc_build, :gem_dir_to_repo_url

    alias libmruby libmruby_objs

    COMPILERS = %w(cc cxx objc asm)
    COMMANDS = COMPILERS + %w(linker archiver yacc gperf git exts mrbc)
    attr_block MRuby::Build::COMMANDS

    Exts = Struct.new(:object, :executable, :library, :presym_preprocessed)

    def initialize(name='host', build_dir=nil, internal: false, &block)
      @name = name.to_s

      unless current = MRuby.targets[@name]
        if ENV['OS'] == 'Windows_NT'
          @exts = Exts.new('.o', '.exe', '.a', '.pi')
        else
          @exts = Exts.new('.o', '', '.a', '.pi')
        end

        build_dir = build_dir || ENV['MRUBY_BUILD_DIR'] || "#{MRUBY_ROOT}/build"

        @file_separator = '/'
        @build_dir = "#{build_dir}/#{@name}"
        @gem_clone_dir = "#{build_dir}/repos/#{@name}"
        @defines = []
        @cc = Command::Compiler.new(self, %w(.c), label: "CC")
        @cxx = Command::Compiler.new(self, %w(.cc .cxx .cpp), label: "CXX")
        @objc = Command::Compiler.new(self, %w(.m), label: "OBJC")
        @asm = Command::Compiler.new(self, %w(.S .asm .s), label: "ASM")
        @linker = Command::Linker.new(self)
        @archiver = Command::Archiver.new(self)
        @yacc = Command::Yacc.new(self)
        @gperf = Command::Gperf.new(self)
        @git = Command::Git.new(self)
        @mrbc = Command::Mrbc.new(self)

        @products = []
        @bins = []
        @gems = MRuby::Gem::List.new
        @libmruby_core_objs = []
        @libmruby_objs = [@libmruby_core_objs]
        @enable_libmruby = true
        @build_mrbtest_lib_only = false
        @cxx_exception_enabled = false
        @cxx_exception_disabled = false
        @cxx_abi_enabled = false
        @enable_bintest = false
        @enable_test = false
        @enable_lock = true
        @enable_presym = true
        @mrbcfile_external = false
        @internal = internal
        @toolchains = []
        @gem_dir_to_repo_url = {}

        MRuby.targets[@name] = current = self
      end

      MRuby::Build.current = current
      begin
        current.instance_eval(&block)
      ensure
        if current.libmruby_enabled? && !current.mrbcfile_external?
          if current.presym_enabled?
            current.create_mrbc_build if current.host? || current.gems["mruby-bin-mrbc"]
          elsif current.host?
            current.build_mrbc_exec
          end
        end
        current.presym = Presym.new(current) if current.presym_enabled?
      end
    end

    def libmruby_enabled?
      @enable_libmruby
    end

    def disable_libmruby
      @enable_libmruby = false
    end

    def debug_enabled?
      @enable_debug
    end

    def enable_debug
      compilers.each do |c|
        c.defines += %w(MRB_DEBUG)
        if toolchains.any? { |toolchain| toolchain == "gcc" }
          c.flags += %w(-g3 -O0)
        end
      end
      @mrbc.compile_options += ' -g'

      @enable_debug = true
    end

    def presym_enabled?
      @enable_presym
    end

    def disable_presym
      if @enable_presym
        @enable_presym = false
        compilers.each{|c| c.defines << "MRB_NO_PRESYM"}
      end
    end

    def disable_lock
      @enable_lock = false
    end

    def lock_enabled?
      Lockfile.enabled? && @enable_lock
    end

    def disable_cxx_exception
      if @cxx_exception_enabled or @cxx_abi_enabled
        raise "cxx_exception already enabled"
      end
      @cxx_exception_disabled = true
    end

    def enable_cxx_exception
      return if @cxx_exception_enabled
      return if @cxx_abi_enabled
      if @cxx_exception_disabled
        raise "cxx_exception disabled"
      end
      @cxx_exception_enabled = true
      compilers.each { |c|
        c.defines += %w(MRB_USE_CXX_EXCEPTION)
        c.flags << c.cxx_exception_flag
      }
      linker.command = cxx.command if toolchains.find { |v| v == 'gcc' }
    end

    def cxx_exception_enabled?
      @cxx_exception_enabled
    end

    def cxx_abi_enabled?
      @cxx_abi_enabled
    end

    def enable_cxx_abi
      return if @cxx_abi_enabled
      if @cxx_exception_enabled
        raise "cxx_exception already enabled"
      end
      compilers.each { |c|
        c.defines += %w(MRB_USE_CXX_EXCEPTION MRB_USE_CXX_ABI)
        c.flags << c.cxx_compile_flag
        c.flags = c.flags.flatten - c.cxx_invalid_flags.flatten
      }
      linker.command = cxx.command if toolchains.find { |v| v == 'gcc' }
      @cxx_abi_enabled = true
    end

    def compile_as_cxx(src, cxx_src = nil, obj = nil, includes = [])
      #
      # If `cxx_src` is specified, this method behaves the same as before as
      # compatibility mode, but `.d` file is not read.
      #
      # If `cxx_src` is omitted, `.d` file is read by using mruby standard
      # Rake rule (C++ source name is also changed).
      #
      if cxx_src
        obj ||= cxx_src + @exts.object
        dsts = [obj]
        dsts << (cxx_src + @exts.presym_preprocessed) if presym_enabled?
        defines = []
        include_paths = ["#{MRUBY_ROOT}/src", *includes]
        dsts.each do |dst|
          file dst => cxx_src do |t|
            cxx.run t.name, t.prerequisites.first, defines, include_paths
          end
        end
      else
        cxx_src = "#{build_dir}/#{src.relative_path.to_s.remove_leading_parents}".ext << "-cxx.cxx"
        obj = cxx_src.ext(@exts.object)
      end

      file cxx_src => [src, __FILE__] do |t|
        mkdir_p File.dirname t.name
        IO.write t.name, <<EOS
#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS

#ifndef MRB_USE_CXX_ABI
extern "C" {
#endif
#include "#{File.absolute_path src}"
#ifndef MRB_USE_CXX_ABI
}
#endif
EOS
      end

      obj
    end

    def enable_bintest
      @enable_bintest = true
    end

    def bintest_enabled?
      @enable_bintest
    end

    def toolchain(name=Toolchain.guess, params={})
      name = name.to_s
      tc = Toolchain.toolchains[name] || begin
        path = "#{MRUBY_ROOT}/tasks/toolchains/#{name}.rake"
        fail "Unknown #{name} toolchain" unless File.exist?(path)
        load path
        Toolchain.toolchains[name]
      end
      tc.setup(self, params)
      @toolchains.unshift name
    end

    def primary_toolchain
      @toolchains.first
    end

    def root
      MRUBY_ROOT
    end

    def enable_test
      @enable_test = true
    end
    alias build_mrbtest enable_test

    def test_enabled?
      @enable_test
    end

    def build_mrbc_exec
      gem :core => 'mruby-bin-mrbc' unless @gems['mruby-bin-mrbc']
    end

    def locks
      Lockfile.build(@name)
    end

    def mrbcfile
      return @mrbcfile if @mrbcfile

      gem_name = "mruby-bin-mrbc"
      if (gem = @gems[gem_name])
        @mrbcfile = exefile("#{gem.build.build_dir}/bin/mrbc")
      elsif !host? && (host = MRuby.targets["host"])
        if (gem = host.gems[gem_name])
          @mrbcfile = exefile("#{gem.build.build_dir}/bin/mrbc")
        elsif host.mrbcfile_external?
          @mrbcfile = host.mrbcfile
        end
      end
      @mrbcfile || fail("external mrbc or mruby-bin-mrbc gem in current('#{@name}') or 'host' build is required")
    end

    def mrbcfile=(path)
      @mrbcfile = path
      @mrbcfile_external = true
    end

    def mrbcfile_external?
      @mrbcfile_external
    end

    def compilers
      COMPILERS.map do |c|
        instance_variable_get("@#{c}")
      end
    end

    def define_rules
      compilers.each do |compiler|
        compiler.defines << "MRB_NO_GEMS" unless enable_gems? && libmruby_enabled?
      end
      [@cc, *(@cxx if cxx_exception_enabled?)].each do |compiler|
        compiler.define_rules(@build_dir, MRUBY_ROOT, @exts.object)
        compiler.define_rules(@build_dir, MRUBY_ROOT, @exts.presym_preprocessed) if presym_enabled?
      end
    end

    def define_installer(src)
      dst = "#{self.class.install_dir}/#{File.basename(src)}"
      file dst => src do
        install_D src, dst
      end
      dst
    end

    def define_installer_if_needed(bin)
      exe = exefile("#{build_dir}/bin/#{bin}")
      host? ? define_installer(exe) : exe
    end

    def filename(name)
      if name.is_a?(Array)
        name.flatten.map { |n| filename(n) }
      else
        name.gsub('/', file_separator)
      end
    end

    def exefile(name)
      if name.is_a?(Array)
        name.flatten.map { |n| exefile(n) }
      elsif File.extname(name).empty?
        "#{name}#{exts.executable}"
      else
        # `name` sometimes have (non-standard) extension (e.g. `.bat`).
        name
      end
    end

    def objfile(name)
      if name.is_a?(Array)
        name.flatten.map { |n| objfile(n) }
      else
        "#{name}#{exts.object}"
      end
    end

    def libfile(name)
      if name.is_a?(Array)
        name.flatten.map { |n| libfile(n) }
      else
        "#{name}#{exts.library}"
      end
    end

    def build_mrbtest_lib_only
      @build_mrbtest_lib_only = true
    end

    def build_mrbtest_lib_only?
      @build_mrbtest_lib_only
    end

    def verbose_flag
      Rake.verbose ? ' -v' : ''
    end

    def run_test
      puts ">>> Test #{name} <<<"
      mrbtest = exefile("#{build_dir}/bin/mrbtest")
      sh "#{filename mrbtest.relative_path}#{verbose_flag}"
      puts
    end

    def run_bintest
      puts ">>> Bintest #{name} <<<"
      targets = @gems.select { |v| File.directory? "#{v.dir}/bintest" }.map { |v| filename v.dir }
      targets << filename(".") if File.directory? "./bintest"
      mrbc = @gems["mruby-bin-mrbc"] ? exefile("#{@build_dir}/bin/mrbc") : mrbcfile
      env = {"BUILD_DIR" => @build_dir, "MRBCFILE" => mrbc}
      sh env, "ruby test/bintest.rb#{verbose_flag} #{targets.join ' '}"
    end

    def print_build_summary
      puts "================================================"
      puts "      Config Name: #{@name}"
      puts " Output Directory: #{self.build_dir.relative_path}"
      puts "         Binaries: #{@bins.join(', ')}" unless @bins.empty?
      unless @gems.empty?
        puts "    Included Gems:"
        gems = @gems.sort_by { |gem| gem.name }
        gems.each do |gem|
          gem_version = " - #{gem.version}" if gem.version != '0.0.0'
          gem_summary = " - #{gem.summary}" if gem.summary
          puts "             #{gem.name}#{gem_version}#{gem_summary}"
          puts "               - Binaries: #{gem.bins.join(', ')}" unless gem.bins.empty?
        end
      end
      puts "================================================"
      puts
    end

    def libmruby_static
      libfile("#{build_dir}/lib/libmruby")
    end

    def libmruby_core_static
      libfile("#{build_dir}/lib/libmruby_core")
    end

    def libraries
      [libmruby_static]
    end

    def host?
      @name == "host"
    end

    def internal?
      @internal
    end

    protected

    attr_writer :presym

    def create_mrbc_build
      exclusions = %i[@name @build_dir @gems @enable_test @enable_bintest @internal]
      name = "#{@name}/mrbc"
      MRuby.targets.delete(name)
      build = self.class.new(name, internal: true){}
      build.build_dir = "#{@build_dir}/mrbc"
      instance_variables.each do |n|
        next if exclusions.include?(n)
        v = instance_variable_get(n)
        v = case v
            when nil, true, false, Numeric; v
            when String, Command; v.clone
            else Marshal.load(Marshal.dump(v))  # deep clone
            end
        build.instance_variable_set(n, v)
      end
      build.build_mrbc_exec
      build.disable_libmruby
      build.disable_presym
      @mrbc_build = build
      self.mrbcfile = build.mrbcfile
      build
    end
  end # Build

  class CrossBuild < Build
    attr_block %w(test_runner)
    # cross compiling targets for building native extensions.
    # host  - arch of where the built binary will run
    # build - arch of the machine building the binary
    attr_accessor :host_target, :build_target

    def initialize(name, build_dir=nil, &block)
      @test_runner = Command::CrossTestRunner.new(self)
      super
      unless mrbcfile_external? || MRuby.targets['host']
        # add minimal 'host'
        MRuby::Build.new('host') do |conf|
          conf.toolchain
          conf.build_mrbc_exec
          conf.disable_libmruby
          conf.disable_presym
        end
      end
    end

    def mrbcfile
      mrbcfile_external? ? super : MRuby::targets['host'].mrbcfile
    end

    def run_test
      @test_runner.runner_options << verbose_flag
      mrbtest = exefile("#{build_dir}/bin/mrbtest")
      if (@test_runner.command == nil)
        puts "You should run #{mrbtest} on target device."
        puts
      else
        @test_runner.run(mrbtest)
      end
    end

    def run_bintest
      puts ">>> Bintest #{name} <<<"
      targets = @gems.select { |v| File.directory? "#{v.dir}/bintest" }.map { |v| filename v.dir }
      targets << filename(".") if File.directory? "./bintest"
      mrbc = @gems["mruby-bin-mrbc"] ? exefile("#{@build_dir}/bin/mrbc") : mrbcfile

      emulator = @test_runner.command
      emulator = @test_runner.shellquote(emulator) if emulator

      env = {
        "BUILD_DIR" => @build_dir,
        "MRBCFILE" => mrbc,
        "EMULATOR" => @test_runner.emulator,
      }
      sh env, "ruby test/bintest.rb#{verbose_flag} #{targets.join ' '}"
    end

    protected

    def create_mrbc_build; end
  end # CrossBuild
end # MRuby
