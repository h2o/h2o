# -*- coding: utf-8 -*-

##
# Minimal Test framework for mruby
#
module MTest


  ##
  # Assertion base class

  class Assertion < Exception; end

  ##
  # Assertion raised when skipping a test

  class Skip < Assertion; end

  module Assertions
    def mu_pp obj
      obj.inspect
    end

    def diff exp, act
      return "Expected: #{mu_pp exp}\n  Actual: #{mu_pp act}"
    end

    def _assertions= n
      @_assertions = n
    end

    def _assertions
      @_assertions = 0 unless @_assertions
      @_assertions
    end

    ##
    # Fails unless +test+ is a true value.

    def assert test, msg = nil
      msg ||= "Failed assertion, no message given."
      self._assertions += 1
      unless test
        msg = msg.call if Proc === msg
        raise MTest::Assertion, msg
      end
      true
    end

    alias assert_true assert

    ##
    # Fails unless +test+ is a false value
    def assert_false test, msg = nil
      msg = message(msg) { "Expected #{mu_pp(test)} to be false" }
      assert test == false, msg
    end

    ##
    # Fails unless the block returns a true value.

    def assert_block msg = nil
      msg = message(msg) { "Expected block to return true value" }
      assert yield, msg
    end

    ##
    # Fails unless +obj+ is empty.

    def assert_empty obj, msg = nil
      msg = message(msg) { "Expected #{mu_pp(obj)} to be empty" }
      assert_respond_to obj, :empty?
      assert obj.empty?, msg
    end

    ##
    # Fails +obj+ is not empty.

    def assert_not_empty obj, msg = nil
      msg = message(msg) { "Expected #{mu_pp(obj)} to be not empty" }
      assert_respond_to obj, :empty?
      assert !obj.empty?, msg
    end

    ##
    # Fails unless <tt>exp == act</tt> printing the difference between
    # the two, if possible.
    #
    # If there is no visible difference but the assertion fails, you
    # should suspect that your #== is buggy, or your inspect output is
    # missing crucial details.
    #
    # For floats use assert_in_delta.
    #
    # See also: MiniTest::Assertions.diff

    def assert_equal exp, act, msg = nil
      msg = message(msg, "") { diff exp, act }
      assert(exp == act, msg)
    end

    ##
    # Fails exp == act
    def assert_not_equal exp, act, msg = nil
      msg = message(msg) {
        "Expected #{mu_pp(exp)} to be not equal #{mu_pp(act)}"
      }
      assert(exp != act, msg)
    end

    ##
    # For comparing Floats.  Fails unless +exp+ and +act+ are within +delta+
    # of each other.
    #
    #   assert_in_delta Math::PI, (22.0 / 7.0), 0.01

    def assert_in_delta exp, act, delta = 0.001, msg = nil
      n = (exp - act).abs
      msg = message(msg) { "Expected #{exp} - #{act} (#{n}) to be < #{delta}" }
      assert delta >= n, msg
    end

    ##
    # For comparing Floats.  Fails unless +exp+ and +act+ have a relative
    # error less than +epsilon+.

    def assert_in_epsilon a, b, epsilon = 0.001, msg = nil
      assert_in_delta a, b, [a, b].min * epsilon, msg
    end

    ##
    # Fails unless +collection+ includes +obj+.

    def assert_include collection, obj, msg = nil
      msg = message(msg) {
        "Expected #{mu_pp(collection)} to include #{mu_pp(obj)}"
      }
      assert_respond_to collection, :include?
      assert collection.include?(obj), msg
    end

    ##
    # Fails +collection+ includes +obj+
    def assert_not_include collection, obj, msg = nil
      msg = message(msg) {
        "Expected #{mu_pp(collection)} to not include #{mu_pp(obj)}"
      }
      assert_respond_to collection, :include?
      assert !collection.include?(obj), msg
    end

    ##
    # Fails unless +obj+ is an instance of +cls+.

    def assert_instance_of cls, obj, msg = nil
      msg = message(msg) {
        "Expected #{mu_pp(obj)} to be an instance of #{cls}, not #{obj.class}"
      }

      assert obj.instance_of?(cls), msg
    end

    ##
    # Fails unless +obj+ is a kind of +cls+.

    def assert_kind_of cls, obj, msg = nil # TODO: merge with instance_of
      msg = message(msg) {
        "Expected #{mu_pp(obj)} to be a kind of #{cls}, not #{obj.class}" }

      assert obj.kind_of?(cls), msg
    end

    ##
    # Fails unless +exp+ is <tt>=~</tt> +act+.

    def assert_match exp, act, msg = nil
      if Object.const_defined?(:Regexp)
        msg = message(msg) { "Expected #{mu_pp(exp)} to match #{mu_pp(act)}" }
        assert_respond_to act, :"=~"
        exp = Regexp.new Regexp.escape exp if String === exp and String === act
        assert exp =~ act, msg
      else
        raise MTest::Skip, "assert_match is not defined, because Regexp is not impl."
      end
    end

    ##
    # Fails unless +obj+ is nil

    def assert_nil obj, msg = nil
      msg = message(msg) { "Expected #{mu_pp(obj)} to be nil" }
      assert obj.nil?, msg
    end

    ##
    # For testing equality operators and so-forth.
    #
    #   assert_operator 5, :<=, 4

    def assert_operator o1, op, o2, msg = nil
      msg = message(msg) { "Expected #{mu_pp(o1)} to be #{op} #{mu_pp(o2)}" }
      assert o1.__send__(op, o2), msg
    end

    ##
    # Fails if stdout or stderr do not output the expected results.
    # Pass in nil if you don't care about that streams output. Pass in
    # "" if you require it to be silent.
    #
    # See also: #assert_silent

    def assert_output stdout = nil, stderr = nil
      out, err = capture_io do
        yield
      end

      x = assert_equal stdout, out, "In stdout" if stdout
      y = assert_equal stderr, err, "In stderr" if stderr

      (!stdout || x) && (!stderr || y)
    end

    ##
    # Fails unless the block raises one of +exp+

    def assert_raise *exp
      msg = "#{exp.pop}\n" if String === exp.last

      begin
        yield
      rescue MTest::Skip => e
        return e if exp.include? MTest::Skip
        raise e
      rescue Exception => e
        excepted = exp.any? do |ex|
          if ex.instance_of?(Module)
            e.kind_of?(ex)
          else
            e.instance_of?(ex)
          end
        end

        assert excepted, exception_details(e, "#{msg}#{mu_pp(exp)} exception expected, not")

        return e
      end
      exp = exp.first if exp.size == 1
      flunk "#{msg}#{mu_pp(exp)} expected but nothing was raised."
    end

    ##
    # Fails unless +obj+ responds to +meth+.

    def assert_respond_to obj, meth, msg = nil
      msg = message(msg, '') {
        "Expected #{mu_pp(obj)} (#{obj.class}) to respond to ##{meth}"
      }
      assert obj.respond_to?(meth), msg
    end

    ##
    # Fails unless +exp+ and +act+ are #equal?

    def assert_same exp, act, msg = nil
      msg = message(msg) {
        data = [mu_pp(act), act.object_id, mu_pp(exp), exp.object_id]
        "Expected %s (oid=%d) to be the same as %s (oid=%d)" % data
      }
      assert exp.equal?(act), msg
    end

    ##
    # +send_ary+ is a receiver, message and arguments.
    #
    # Fails unless the call returns a true value
    # TODO: I should prolly remove this from specs

    def assert_send send_ary, m = nil
      recv, msg, *args = send_ary
      m = message(m) {
        "Expected #{mu_pp(recv)}.#{msg}(*#{mu_pp(args)}) to return true" }
      assert recv.__send__(msg, *args), m
    end

    ##
    # Fails if the block outputs anything to stderr or stdout.
    #
    # See also: #assert_output

    def assert_silent
      assert_output "", "" do
        yield
      end
    end

    ##
    # Fails unless the block throws +sym+

    def assert_throws sym, msg = nil
      default = "Expected #{mu_pp(sym)} to have been thrown"
      caught = true
      catch(sym) do
        begin
          yield
        rescue ArgumentError => e     # 1.9 exception
          default += ", not #{e.message.split(' ').last}"
        rescue NameError => e         # 1.8 exception
          default += ", not #{e.name.inspect}"
        end
        caught = false
      end

      assert caught, message(msg) { default }
    end

    ##
    # Returns a proc that will output +msg+ along with the default message.

    def message msg = nil, ending = ".", &default
      Proc.new{
        custom_message = "#{msg}.\n" unless msg.nil? or msg.to_s.empty?
        "#{custom_message}#{default.call}#{ending}"
      }
    end

    ##
    # used for counting assertions

    def pass msg = nil
      assert true
    end

    ##
    # Skips the current test. Gets listed at the end of the run but
    # doesn't cause a failure exit code.

    # disable backtrace for mruby

    def skip msg = nil
      msg ||= "Skipped, no message given"
      raise MTest::Skip, msg
    end

    ##
    # Returns details for exception +e+

    # disable backtrace for mruby

    def exception_details e, msg
      [
       "#{msg}",
       "Class: <#{e.class}>",
       "Message: <#{e.message.inspect}>",
#       "---Backtrace---",
#       "#{MiniTest::filter_backtrace(e.backtrace).join("\n")}",
#       "---------------",
      ].join "\n"
    end

    ##
    # Fails with +msg+

    def flunk msg = nil
      msg ||= "Epic Fail!"
      assert false, msg
    end

  end

  class Unit
    attr_accessor :report, :failures, :errors, :skips
    attr_accessor :test_count, :assertion_count
    attr_accessor :start_time
    attr_accessor :help
    attr_accessor :verbose
    attr_writer   :options

    def options
      @options ||= {}
    end

    @@out = $stdout
    @@runner = nil

    def self.output
      @@out
    end

    def self.output= stream
      @@out = stream
    end

    def self.runnner= runner
      @@runner = runnner
    end

    def self.runner
      @@runner = self.new  unless @@runner
      @@runner
    end

    def output
      self.class.output
    end

    def puts *a
      output.puts(*a)
    end

    def print *a
      output.print(*a)
    end

    def puke klass, meth, e
      e = case e
          when MTest::Skip
            @skips += 1
            "Skipped:\n#{meth}(#{klass}) #{e.inspect}\n"
          when MTest::Assertion
            @failures += 1
            "Failure:\n#{meth}(#{klass}) #{e.inspect}\n"
          else
            @errors += 1
            "Error:\n#{meth}(#{klass}): #{e.class}, #{e.inspect}\n"
          end
      @report << e
      e[0, 1]
    end

    def initialize
      @report = []
      @errors = @failures = @skips = 0
      @verbose = false
    end

    def run args = []
      self.class.runner._run(args)
    end

    def mrbtest
      suites = TestCase.send "test_suites"
      return if suites.empty?

      @test_cound, @assertion_count = 0, 0

      results = _run_suites suites

      @test_count      = results.map{ |r| r[0] }.inject(0) { |sum, tc| sum + tc }
      @assertion_count = results.map{ |r| r[1] }.inject(0) { |sum, ac| sum + ac }

      $ok_test += (test_count.to_i - failures.to_i - errors.to_i - skips.to_i)
      $ko_test += failures.to_i
      $kill_test += errors.to_i
      report.each_with_index do |msg, i|
        $asserts << "MTest #{i+1}) #{msg}"
      end

      TestCase.reset
    end

    def _run args = []
      _run_tests
      @test_count ||= 0
      @test_count > 0 ? failures + errors : nil
    end

    def _run_tests
      suites = TestCase.send "test_suites"
      return if suites.empty?

      start = Time.now

      puts
      puts "# Running tests:"
      puts

      @test_count, @assertion_count = 0, 0

      results = _run_suites suites

      @test_count      = results.map{ |r| r[0] }.inject(0) { |sum, tc| sum + tc }
      @assertion_count = results.map{ |r| r[1] }.inject(0) { |sum, ac| sum + ac }

      t = Time.now - start

      puts
      puts
      puts sprintf("Finished tests in %.6fs, %.4f tests/s, %.4f assertions/s.",
        t, test_count / t, assertion_count / t)

      report.each_with_index do |msg, i|
        puts sprintf("\n%3d) %s", i+1, msg)
      end

      puts

      status
    end

    def _run_suites suites
      suites.map { |suite| _run_suite suite }
    end

    def _run_suite suite
      header = "test_suite_header"
      puts send(header, suite) if respond_to? header

      assertions = suite.send("test_methods").map do |method|
        inst = suite.new method
        inst._assertions = 0

        print "#{suite}##{method} = " if @verbose

        @start_time = Time.now
        result = inst.run self
        time = Time.now - @start_time

        print sprintf("%.2f s = ", time) if @verbose
        print result
        puts if @verbose

        inst._assertions
      end

      return assertions.size, assertions.inject(0) { |sum, n| sum + n }
    end

    def status io = self.output
      format = "%d tests, %d assertions, %d failures, %d errors, %d skips"
      io.puts sprintf(format, test_count, assertion_count, failures, errors, skips)
    end

    class TestCase
      attr_reader :__name__

      @@test_suites = {}

      def run runner
        result = ""
        begin
          @passed = nil
          self.setup
          self.run_setup_hooks
          self.__send__ self.__name__
          result = "." unless io?
          @passed = true
        rescue Exception => e
          @passed = false
          result = runner.puke self.class, self.__name__, e
        ensure
          begin
            self.run_teardown_hooks
            self.teardown
          rescue Exception => e
            result = runner.puke self.class, self.__name__, e
          end
        end
        result
      end

      def initialize name = self.to_s
        @__name__ = name
        @__io__ = nil
        @passed = nil
      end

      def io
        @__io__ = true
        MTest::Unit.output
      end

      def io?
        @__io__
      end

      def self.reset
        @@test_suites = {}
      end

      reset

      def self.inherited klass
        @@test_suites[klass] = true
        klass.reset_setup_teardown_hooks
      end

      def self.test_order
        :random
      end

      def self.test_suites
        hash = {}
        @@test_suites.keys.each{ |ts| hash[ts.to_s] = ts }
        hash.keys.sort.map{ |key| hash[key] }
      end

      def self.test_methods # :nodoc:
        methods = []
        self.new.methods(true).each do |m|
          methods << m.to_s  if m.to_s.index('test') == 0
        end

        case self.test_order
        when :random then
          max = methods.size
          # TODO: methods.sort.sort_by { rand max }
          methods
        when :alpha, :sorted then
          methods.sort
        else
          raise "Unknown test_order: #{self.test_order.inspect}"
        end
      end


      def passed?
        @passed
      end

      def setup; end
      def teardown; end
      def self.reset_setup_teardown_hooks
        @setup_hooks = []
        @teardown_hooks = []
      end
      reset_setup_teardown_hooks

      def self.add_setup_hook arg=nil, &block
        hook = arg || block
        @setup_hooks << hook
      end

      def self.setup_hooks # :nodoc:
        if superclass.respond_to? :setup_hooks then
          superclass.setup_hooks
        else
          []
        end + @setup_hooks
      end

      def run_setup_hooks # :nodoc:
        self.class.setup_hooks.each do |hook|
          if hook.respond_to?(:arity) && hook.arity == 1
            hook.call(self)
          else
            hook.call
          end
        end
      end

      def self.add_teardown_hook arg=nil, &block
        hook = arg || block
        @teardown_hooks << hook
      end

      def self.teardown_hooks # :nodoc:
        if superclass.respond_to? :teardown_hooks then
          superclass.teardown_hooks
        else
          []
        end + @teardown_hooks
      end

      def run_teardown_hooks # :nodoc:
        self.class.teardown_hooks.reverse.each do |hook|
          if hook.respond_to?(:arity) && hook.arity == 1
            hook.call(self)
          else
            hook.call
          end
        end
      end


      include MTest::Assertions
    end
  end
end

if __FILE__ == $0
  class Test4MTest < MTest::Unit::TestCase
    def setup
      puts '*setup'
    end

    def teardown
      puts '*teardown'
    end

    def test_sample
      puts '*test_sample'
      assert(true, 'true sample test')
      assert(true)
    end
  end

  MTest::Unit.new.run
end
