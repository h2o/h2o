require 'forwardable'
autoload :TSort, 'tsort'
autoload :Shellwords, 'shellwords'

module MRuby
  module Gem
    class << self
      attr_accessor :current
    end

    class Specification
      include Rake::DSL
      extend Forwardable
      def_delegators :@build, :filename, :objfile, :libfile, :exefile

      attr_accessor :name, :dir, :build
      alias mruby build
      attr_accessor :build_config_initializer

      attr_accessor :version
      attr_accessor :description, :summary
      attr_accessor :homepage
      attr_accessor :licenses, :authors
      alias :license= :licenses=
      alias :author= :authors=

      attr_accessor :rbfiles, :objs
      attr_writer :test_objs, :test_rbfiles
      attr_accessor :test_args, :test_preload

      attr_accessor :bins

      attr_accessor :requirements
      attr_reader :dependencies, :conflicts

      attr_accessor :export_include_paths

      attr_reader :generate_functions

      attr_block MRuby::Build::COMMANDS

      def initialize(name, &block)
        @name = name
        @initializer = block
        @version = "0.0.0"
        @dependencies = []
        @conflicts = []
        MRuby::Gem.current = self
      end

      def setup
        return if defined?(@bins)  # return if already set up

        MRuby::Gem.current = self
        MRuby::Build::COMMANDS.each do |command|
          instance_variable_set("@#{command}", @build.send(command).clone)
        end
        @linker.run_attrs.each(&:clear)

        @rbfiles = Dir.glob("#{@dir}/mrblib/**/*.rb").sort
        @objs = srcs_to_objs("src")

        @test_preload = nil # 'test/assert.rb'
        @test_args = {}

        @bins = []
        @cdump = true

        @requirements = []
        @export_include_paths = []
        @export_include_paths << "#{dir}/include" if File.directory? "#{dir}/include"

        instance_eval(&@initializer)

        @generate_functions = !(@rbfiles.empty? && @objs.empty?)
        @objs << objfile("#{build_dir}/gem_init") if @generate_functions

        if !name || !licenses || !authors
          fail "#{name || dir} required to set name, license(s) and author(s)"
        end

        build.libmruby_objs << @objs

        instance_eval(&@build_config_initializer) if @build_config_initializer

        repo_url = build.gem_dir_to_repo_url[dir]
        build.locks[repo_url]['version'] = version if repo_url
      end

      def setup_compilers
        (core? ? [@cc, *(@cxx if build.cxx_exception_enabled?)] : compilers).each do |compiler|
          compiler.define_rules build_dir, @dir, @build.exts.presym_preprocessed if build.presym_enabled?
          compiler.define_rules build_dir, @dir, @build.exts.object
          compiler.defines << %Q[MRBGEM_#{funcname.upcase}_VERSION=#{version}]
          compiler.include_paths << "#{@dir}/include" if File.directory? "#{@dir}/include"
        end

        define_gem_init_builder if @generate_functions
      end

      def for_windows?
        if build.kind_of?(MRuby::CrossBuild)
          return %w(x86_64-w64-mingw32 i686-w64-mingw32).include?(build.host_target)
        elsif build.kind_of?(MRuby::Build)
          return ('A'..'Z').to_a.any? { |vol| Dir.exist?("#{vol}:") }
        end
        return false
      end

      def disable_cdump
        @cdump = false
      end

      def cdump?
        build.presym_enabled? && @cdump
      end

      def core?
        @dir.start_with?("#{MRUBY_ROOT}/mrbgems/")
      end

      def bin?
        @bins.size > 0
      end

      def add_dependency(name, *requirements)
        default_gem = requirements.last.kind_of?(Hash) ? requirements.pop : nil
        requirements = ['>= 0.0.0'] if requirements.empty?
        requirements.flatten!
        @dependencies << {:gem => name, :requirements => requirements, :default => default_gem}
      end

      def add_test_dependency(*args)
        add_dependency(*args) if build.test_enabled? || build.bintest_enabled?
      end

      def add_conflict(name, *req)
        @conflicts << {:gem => name, :requirements => req.empty? ? nil : req}
      end

      def build_dir
        "#{build.build_dir}/mrbgems/#{name}"
      end

      def test_rbireps
        "#{build_dir}/gem_test.c"
      end

      def test_objs
        @test_objs ||= srcs_to_objs("test")
      end

      def test_rbfiles
        @test_rbfiles ||= Dir["#{@dir}/test/**/*.rb"].sort!
      end

      def search_package(name, version_query=nil)
        package_query = name
        package_query += " #{version_query}" if version_query
        _pp "PKG-CONFIG", package_query
        escaped_package_query = Shellwords.escape(package_query)
        if system("pkg-config --exists #{escaped_package_query}")
          cc.flags += [`pkg-config --cflags #{escaped_package_query}`.strip]
          cxx.flags += [`pkg-config --cflags #{escaped_package_query}`.strip]
          linker.flags_before_libraries += [`pkg-config --libs #{escaped_package_query}`.strip]
          true
        else
          false
        end
      end

      def funcname
        @funcname ||= @name.gsub('-', '_')
      end

      def compilers
        MRuby::Build::COMPILERS.map do |c|
          instance_variable_get("@#{c}")
        end
      end

      def srcs_to_objs(src_dir_from_gem_dir)
        exts = compilers.flat_map{|c| c.source_exts} * ","
        Dir["#{@dir}/#{src_dir_from_gem_dir}/*{#{exts}}"].map do |f|
          objfile(f.relative_path_from(@dir).to_s.pathmap("#{build_dir}/%X"))
        end
      end

      def define_gem_init_builder
        file "#{build_dir}/gem_init.c" => [build.mrbcfile, __FILE__] + [rbfiles].flatten do |t|
          mkdir_p build_dir
          generate_gem_init("#{build_dir}/gem_init.c")
        end
      end

      def generate_gem_init(fname)
        _pp "GEN", fname.relative_path
        open(fname, 'w') do |f|
          print_gem_init_header f
          unless rbfiles.empty?
            opts = {cdump: cdump?, static: true}
            if cdump?
              build.mrbc.run f, rbfiles, "gem_mrblib_#{funcname}_proc", **opts
            else
              build.mrbc.run f, rbfiles, "gem_mrblib_irep_#{funcname}", **opts
            end
          end
          f.puts %Q[void mrb_#{funcname}_gem_init(mrb_state *mrb);]
          f.puts %Q[void mrb_#{funcname}_gem_final(mrb_state *mrb);]
          f.puts %Q[]
          f.puts %Q[void GENERATED_TMP_mrb_#{funcname}_gem_init(mrb_state *mrb) {]
          f.puts %Q[  int ai = mrb_gc_arena_save(mrb);]
          f.puts %Q[  gem_mrblib_#{funcname}_proc_init_syms(mrb);] if !rbfiles.empty? && cdump?
          f.puts %Q[  mrb_#{funcname}_gem_init(mrb);] if objs != [objfile("#{build_dir}/gem_init")]
          unless rbfiles.empty?
            if cdump?
              f.puts %Q[  mrb_load_proc(mrb, gem_mrblib_#{funcname}_proc);]
            else
              f.puts %Q[  mrb_load_irep(mrb, gem_mrblib_irep_#{funcname});]
            end
            f.puts %Q[  if (mrb->exc) {]
            f.puts %Q[    mrb_print_error(mrb);]
            f.puts %Q[    mrb_close(mrb);]
            f.puts %Q[    exit(EXIT_FAILURE);]
            f.puts %Q[  }]
            f.puts %Q[  struct REnv *e = mrb_vm_ci_env(mrb->c->cibase);]
            f.puts %Q[  mrb_vm_ci_env_set(mrb->c->cibase, NULL);]
            f.puts %Q[  mrb_env_unshare(mrb, e);]
          end
          f.puts %Q[  mrb_gc_arena_restore(mrb, ai);]
          f.puts %Q[}]
          f.puts %Q[]
          f.puts %Q[void GENERATED_TMP_mrb_#{funcname}_gem_final(mrb_state *mrb) {]
          f.puts %Q[  mrb_#{funcname}_gem_final(mrb);] if objs != [objfile("#{build_dir}/gem_init")]
          f.puts %Q[}]
        end
      end # generate_gem_init

      def print_gem_comment(f)
        f.puts %Q[/*]
        f.puts %Q[ * This file is loading the irep]
        f.puts %Q[ * Ruby GEM code.]
        f.puts %Q[ *]
        f.puts %Q[ * IMPORTANT:]
        f.puts %Q[ *   This file was generated!]
        f.puts %Q[ *   All manual changes will get lost.]
        f.puts %Q[ */]
      end

      def print_gem_init_header(f)
        print_gem_comment(f)
        if rbfiles.empty?
          f.puts %Q[#include <mruby.h>]
        else
          f.puts %Q[#include <stdlib.h>]
          unless cdump?
            f.puts %Q[#include <mruby.h>]
            f.puts %Q[#include <mruby/proc.h>]
          end
        end
      end

      def print_gem_test_header(f)
        print_gem_comment(f)
        f.puts %Q[#include <stdio.h>]
        f.puts %Q[#include <stdlib.h>]
        f.puts %Q[#include <mruby.h>]
        f.puts %Q[#include <mruby/irep.h>]
        f.puts %Q[#include <mruby/variable.h>]
        f.puts %Q[#include <mruby/hash.h>] unless test_args.empty?
      end

      def custom_test_init?
        !test_objs.empty?
      end

      def version_ok?(req_versions)
        req_versions.map do |req|
          cmp, ver = req.split
          cmp_result = Version.new(version) <=> Version.new(ver)
          case cmp
          when '=' then cmp_result == 0
          when '!=' then cmp_result != 0
          when '>' then cmp_result == 1
          when '<' then cmp_result == -1
          when '>=' then cmp_result >= 0
          when '<=' then cmp_result <= 0
          when '~>'
            Version.new(version).twiddle_wakka_ok?(Version.new(ver))
          else
            fail "Comparison not possible with '#{cmp}'"
          end
        end.all?
      end
    end # Specification

    class Version
      include Comparable
      include Enumerable

      def <=>(other)
        ret = 0
        own = to_enum

        other.each do |oth|
          begin
            ret = own.next <=> oth
          rescue StopIteration
            ret = 0 <=> oth
          end

          break unless ret == 0
        end

        ret
      end

      # ~> compare algorithm
      #
      # Example:
      #    ~> 2     means >= 2.0.0 and < 3.0.0
      #    ~> 2.2   means >= 2.2.0 and < 3.0.0
      #    ~> 2.2.2 means >= 2.2.2 and < 2.3.0
      def twiddle_wakka_ok?(other)
        gr_or_eql = (self <=> other) >= 0
        still_major_or_minor = (self <=> other.skip_major_or_minor) < 0
        gr_or_eql and still_major_or_minor
      end

      def skip_major_or_minor
        a = @ary.dup
        a << 0 if a.size == 1 # ~> 2 can also be represented as ~> 2.0
        a.slice!(-1)
        a[-1] = a[-1].succ
        a
      end

      def initialize(str)
        @str = str
        @ary = @str.split('.').map(&:to_i)
      end

      def each(&block); @ary.each(&block); end
      def [](index); @ary[index]; end
      def []=(index, value)
        @ary[index] = value
        @str = @ary.join('.')
      end
      def slice!(index)
        @ary.slice!(index)
        @str = @ary.join('.')
      end
    end # Version

    class List
      include Enumerable

      def initialize
        @ary = []
      end

      def each(&b)
        @ary.each(&b)
      end

      def [](name)
        @ary.detect {|g| g.name == name}
      end

      def <<(gem)
        unless @ary.detect {|g| g.dir == gem.dir }
          @ary << gem
        else
          # GEM was already added to this list
        end
      end

      def empty?
        @ary.empty?
      end

      def default_gem_params dep
        if dep[:default]; dep
        elsif File.exist? "#{MRUBY_ROOT}/mrbgems/#{dep[:gem]}" # check core
          { :gem => dep[:gem], :default => { :core => dep[:gem] } }
        else # fallback to mgem-list
          { :gem => dep[:gem], :default => { :mgem => dep[:gem] } }
        end
      end

      def generate_gem_table build
        gem_table = each_with_object({}) { |spec, h| h[spec.name] = spec }

        default_gems = {}
        each do |g|
          g.dependencies.each do |dep|
            default_gems[dep[:gem]] ||= default_gem_params(dep)
          end
        end

        until default_gems.empty?
          def_name, def_gem = default_gems.shift
          next if gem_table[def_name]

          spec = gem_table[def_name] = build.gem(def_gem[:default])
          fail "Invalid gem name: #{spec.name} (Expected: #{def_name})" if spec.name != def_name
          spec.setup

          spec.dependencies.each do |dep|
            default_gems[dep[:gem]] ||= default_gem_params(dep)
          end
        end

        each do |g|
          g.dependencies.each do |dep|
            name = dep[:gem]
            req_versions = dep[:requirements]
            dep_g = gem_table[name]

            # check each GEM dependency against all available GEMs
            if dep_g.nil?
              fail "The GEM '#{g.name}' depends on the GEM '#{name}' but it could not be found"
            end
            unless dep_g.version_ok? req_versions
              fail "#{name} version should be #{req_versions.join(' and ')} but was '#{dep_g.version}'"
            end
          end

          cfls = g.conflicts.select { |c|
            cfl_g = gem_table[c[:gem]]
            cfl_g and cfl_g.version_ok?(c[:requirements] || ['>= 0.0.0'])
          }.map { |c| "#{c[:gem]}(#{gem_table[c[:gem]].version})" }
          fail "Conflicts of gem `#{g.name}` found: #{cfls.join ', '}" unless cfls.empty?
        end

        gem_table
      end

      def tsort_dependencies ary, table, all_dependency_listed = false
        unless all_dependency_listed
          left = ary.dup
          until left.empty?
            v = left.pop
            table[v].dependencies.each do |dep|
              left.push dep[:gem]
              ary.push dep[:gem]
            end
          end
        end

        ary.uniq!
        table.instance_variable_set :@root_gems, ary
        class << table
          include TSort
          def tsort_each_node &b
            @root_gems.each &b
          end

          def tsort_each_child(n, &b)
            fetch(n).dependencies.each do |v|
              b.call v[:gem]
            end
          end
        end

        begin
          table.tsort.map { |v| table[v] }
        rescue TSort::Cyclic => e
          fail "Circular mrbgem dependency found: #{e.message}"
        end
      end

      def check(build)
        gem_table = generate_gem_table build

        @ary = tsort_dependencies gem_table.keys, gem_table, true

        each(&:setup_compilers)

        each do |g|
          import_include_paths(g)
        end
      end

      def import_include_paths(g)
        gem_table = each_with_object({}) { |spec, h| h[spec.name] = spec }

        g.dependencies.each do |dep|
          dep_g = gem_table[dep[:gem]]
          # We can do recursive call safely
          # as circular dependency has already detected in the caller.
          import_include_paths(dep_g)

          dep_g.export_include_paths.uniq!
          g.compilers.each do |compiler|
            compiler.include_paths += dep_g.export_include_paths
            g.export_include_paths += dep_g.export_include_paths
            compiler.include_paths.uniq!
            g.export_include_paths.uniq!
          end
        end
      end

      def linker_attrs(gem=nil)
        gems = self.reject{|g| g.bin?}  # library gems
        gems << gem unless gem.nil?
        gems.map{|g| g.linker.run_attrs}.transpose
      end
    end # List
  end # Gem

  GemBox = Object.new
  class << GemBox
    attr_accessor :path

    def new(&block); block.call(self); end
    def config=(obj); @config = obj; end
    def gem(gemdir, &block); @config.gem(gemdir, &block); end
    def gembox(gemfile); @config.gembox(gemfile); end
  end # GemBox
end # MRuby
