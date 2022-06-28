require "mruby-core-ext"
require "mruby/build/load_gems"
require "mruby/build/command"

module MRuby
  autoload :Gem, "mruby/gem"
  autoload :Lockfile, "mruby/lockfile"

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
    end

    def initialize(name, &block)
      @name, @initializer = name.to_s, block
      MRuby::Toolchain.toolchains[@name] = self
    end

    def setup(conf,params={})
      conf.instance_exec(conf, params, &@initializer)
    end

    self.toolchains = {}
  end

  class Build
    class << self
      attr_accessor :current
    end
    include Rake::DSL
    include LoadGems
    attr_accessor :name, :bins, :exts, :file_separator, :build_dir, :gem_clone_dir
    attr_reader :libmruby_objs, :gems, :toolchains, :gem_dir_to_repo_url
    attr_writer :enable_bintest, :enable_test

    alias libmruby libmruby_objs

    COMPILERS = %w(cc cxx objc asm)
    COMMANDS = COMPILERS + %w(linker archiver yacc gperf git exts mrbc)
    attr_block MRuby::Build::COMMANDS

    Exts = Struct.new(:object, :executable, :library)

    def initialize(name='host', build_dir=nil, &block)
      @name = name.to_s

      unless MRuby.targets[@name]
        if ENV['OS'] == 'Windows_NT'
          @exts = Exts.new('.o', '.exe', '.a')
        else
          @exts = Exts.new('.o', '', '.a')
        end

        build_dir = build_dir || ENV['MRUBY_BUILD_DIR'] || "#{MRUBY_ROOT}/build"

        @file_separator = '/'
        @build_dir = "#{build_dir}/#{@name}"
        @gem_clone_dir = "#{build_dir}/repos/#{@name}"
        @cc = Command::Compiler.new(self, %w(.c))
        @cxx = Command::Compiler.new(self, %w(.cc .cxx .cpp))
        @objc = Command::Compiler.new(self, %w(.m))
        @asm = Command::Compiler.new(self, %w(.S .asm))
        @linker = Command::Linker.new(self)
        @archiver = Command::Archiver.new(self)
        @yacc = Command::Yacc.new(self)
        @gperf = Command::Gperf.new(self)
        @git = Command::Git.new(self)
        @mrbc = Command::Mrbc.new(self)

        @bins = []
        @gems, @libmruby_objs = MRuby::Gem::List.new, []
        @build_mrbtest_lib_only = false
        @cxx_exception_enabled = false
        @cxx_exception_disabled = false
        @cxx_abi_enabled = false
        @enable_bintest = false
        @enable_test = false
        @enable_lock = true
        @toolchains = []
        @gem_dir_to_repo_url = {}

        MRuby.targets[@name] = self
      end

      MRuby::Build.current = MRuby.targets[@name]
      MRuby.targets[@name].instance_eval(&block)

      build_mrbc_exec if name == 'host'
      build_mrbtest if test_enabled?
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
        c.defines += %w(MRB_ENABLE_CXX_EXCEPTION)
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
        c.defines += %w(MRB_ENABLE_CXX_EXCEPTION MRB_ENABLE_CXX_ABI)
        c.flags << c.cxx_compile_flag
        c.flags = c.flags.flatten - c.cxx_invalid_flags.flatten
      }
      linker.command = cxx.command if toolchains.find { |v| v == 'gcc' }
      @cxx_abi_enabled = true
    end

    def compile_as_cxx src, cxx_src, obj = nil, includes = []
      obj = objfile(cxx_src) if obj.nil?

      file cxx_src => [src, __FILE__] do |t|
        mkdir_p File.dirname t.name
        IO.write t.name, <<EOS
#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS

#ifndef MRB_ENABLE_CXX_ABI
extern "C" {
#endif
#include "#{File.absolute_path src}"
#ifndef MRB_ENABLE_CXX_ABI
}
#endif
EOS
      end

      file obj => cxx_src do |t|
        cxx.run t.name, t.prerequisites.first, [], ["#{MRUBY_ROOT}/src"] + includes
      end

      obj
    end

    def enable_bintest
      @enable_bintest = true
    end

    def bintest_enabled?
      @enable_bintest
    end

    def toolchain(name, params={})
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

    def test_enabled?
      @enable_test
    end

    def build_mrbtest
      gem :core => 'mruby-test'
    end

    def build_mrbc_exec
      gem :core => 'mruby-bin-mrbc'
    end

    def locks
      Lockfile.build(@name)
    end

    def mrbcfile
      return @mrbcfile if @mrbcfile

      mrbc_build = MRuby.targets['host']
      gems.each { |v| mrbc_build = self if v.name == 'mruby-bin-mrbc' }
      @mrbcfile = mrbc_build.exefile("#{mrbc_build.build_dir}/bin/mrbc")
    end

    def compilers
      COMPILERS.map do |c|
        instance_variable_get("@#{c}")
      end
    end

    def define_rules
      compilers.each do |compiler|
        if respond_to?(:enable_gems?) && enable_gems?
          compiler.defines -= %w(DISABLE_GEMS)
        else
          compiler.defines += %w(DISABLE_GEMS)
        end
        compiler.define_rules build_dir, File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))
      end
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
      sh "ruby test/bintest.rb#{verbose_flag} #{targets.join ' '}"
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
  end # Build

  class CrossBuild < Build
    attr_block %w(test_runner)
    # cross compiling targets for building native extensions.
    # host  - arch of where the built binary will run
    # build - arch of the machine building the binary
    attr_accessor :host_target, :build_target

    def initialize(name, build_dir=nil, &block)
      @endian = nil
      @test_runner = Command::CrossTestRunner.new(self)
      super
    end

    def mrbcfile
      MRuby.targets['host'].exefile("#{MRuby.targets['host'].build_dir}/bin/mrbc")
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
  end # CrossBuild
end # MRuby
