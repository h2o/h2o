require "mruby/build/load_gems"
require "mruby/build/command"

module MRuby
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
      MRuby::Toolchain.toolchains ||= {}
      MRuby::Toolchain.toolchains[@name] = self
    end

    def setup(conf,params={})
      conf.instance_exec(conf, params, &@initializer)
    end

    def self.load
      Dir.glob("#{MRUBY_ROOT}/tasks/toolchains/*.rake").each do |file|
        Kernel.load file
      end
    end
  end
  Toolchain.load

  class Build
    class << self
      attr_accessor :current
    end
    include Rake::DSL
    include LoadGems
    attr_accessor :name, :bins, :exts, :file_separator, :build_dir, :gem_clone_dir
    attr_reader :libmruby, :gems, :toolchains
    attr_writer :enable_bintest, :enable_test

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
        @gem_clone_dir = "#{build_dir}/mrbgems"
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
        @gems, @libmruby = MRuby::Gem::List.new, []
        @build_mrbtest_lib_only = false
        @cxx_exception_enabled = false
        @cxx_exception_disabled = false
        @cxx_abi_enabled = false
        @enable_bintest = false
        @enable_test = false
        @toolchains = []

        MRuby.targets[@name] = self
      end

      MRuby::Build.current = MRuby.targets[@name]
      MRuby.targets[@name].instance_eval(&block)

      build_mrbc_exec if name == 'host'
      build_mrbtest if test_enabled?
    end

    def enable_debug
      compilers.each do |c|
        c.defines += %w(MRB_DEBUG)
        if toolchains.any? { |toolchain| toolchain == "gcc" }
          c.flags += %w(-g3 -O0)
        end
      end
      @mrbc.compile_options += ' -g'
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
      }
      compilers.each { |c| c.flags << c.cxx_compile_flag }
      linker.command = cxx.command if toolchains.find { |v| v == 'gcc' }
      @cxx_abi_enabled = true
    end

    def compile_as_cxx src, cxx_src, obj = nil, includes = []
      src = File.absolute_path src
      cxx_src = File.absolute_path cxx_src
      obj = objfile(cxx_src) if obj.nil?

      file cxx_src => [src, __FILE__] do |t|
        FileUtils.mkdir_p File.dirname t.name
        IO.write t.name, <<EOS
#define __STDC_CONSTANT_MACROS
#define __STDC_LIMIT_MACROS

#ifndef MRB_ENABLE_CXX_ABI
extern "C" {
#endif
#include "#{src}"
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
      tc = Toolchain.toolchains[name.to_s]
      fail "Unknown #{name} toolchain" unless tc
      tc.setup(self, params)
      @toolchains.unshift name.to_s
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
        '"%s"' % name.gsub('/', file_separator)
      end
    end

    def cygwin_filename(name)
      if name.is_a?(Array)
        name.flatten.map { |n| cygwin_filename(n) }
      else
        '"%s"' % `cygpath -w "#{filename(name)}"`.strip
      end
    end

    def exefile(name)
      if name.is_a?(Array)
        name.flatten.map { |n| exefile(n) }
      else
        "#{name}#{exts.executable}"
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

    def run_test
      puts ">>> Test #{name} <<<"
      mrbtest = exefile("#{build_dir}/bin/mrbtest")
      sh "#{filename mrbtest.relative_path}#{$verbose ? ' -v' : ''}"
      puts
    end

    def run_bintest
      targets = @gems.select { |v| File.directory? "#{v.dir}/bintest" }.map { |v| filename v.dir }
      targets << filename(".") if File.directory? "./bintest"
      sh "ruby test/bintest.rb #{targets.join ' '}"
    end

    def print_build_summary
      puts "================================================"
      puts "      Config Name: #{@name}"
      puts " Output Directory: #{self.build_dir.relative_path}"
      puts "         Binaries: #{@bins.join(', ')}" unless @bins.empty?
      unless @gems.empty?
        puts "    Included Gems:"
        @gems.map do |gem|
          gem_version = " - #{gem.version}" if gem.version != '0.0.0'
          gem_summary = " - #{gem.summary}" if gem.summary
          puts "             #{gem.name}#{gem_version}#{gem_summary}"
          puts "               - Binaries: #{gem.bins.join(', ')}" unless gem.bins.empty?
        end
      end
      puts "================================================"
      puts
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
      @test_runner.runner_options << ' -v' if $verbose
      mrbtest = exefile("#{build_dir}/bin/mrbtest")
      if (@test_runner.command == nil)
        puts "You should run #{mrbtest} on target device."
        puts
      else
        @test_runner.run(mrbtest)
      end
    end

    def big_endian
      if @endian
        puts "Endian has already specified as #{@endian}."
        return
      end
      @endian = :big
      @mrbc.compile_options += ' -E'
      compilers.each do |c|
        c.defines += %w(MRB_ENDIAN_BIG)
      end
    end

    def little_endian
      if @endian
        puts "Endian has already specified as #{@endian}."
        return
      end
      @endian = :little
      @mrbc.compile_options += ' -e'
    end
  end # CrossBuild
end # MRuby
