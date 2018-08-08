##
# enumerator.rb Enumerator class
# See Copyright Notice in mruby.h

##
# A class which allows both internal and external iteration.
#
# An Enumerator can be created by the following methods.
# - {Kernel#to_enum}
# - {Kernel#enum_for}
# - {Enumerator#initialize Enumerator.new}
#
# Most methods have two forms: a block form where the contents
# are evaluated for each item in the enumeration, and a non-block form
# which returns a new Enumerator wrapping the iteration.
#
#       enumerator = %w(one two three).each
#       puts enumerator.class # => Enumerator
#
#       enumerator.each_with_object("foo") do |item, obj|
#         puts "#{obj}: #{item}"
#       end
#
#       # foo: one
#       # foo: two
#       # foo: three
#
#       enum_with_obj = enumerator.each_with_object("foo")
#       puts enum_with_obj.class # => Enumerator
#
#       enum_with_obj.each do |item, obj|
#         puts "#{obj}: #{item}"
#       end
#
#       # foo: one
#       # foo: two
#       # foo: three
#
# This allows you to chain Enumerators together.  For example, you
# can map a list's elements to strings containing the index
# and the element as a string via:
#
#       puts %w[foo bar baz].map.with_index { |w, i| "#{i}:#{w}" }
#       # => ["0:foo", "1:bar", "2:baz"]
#
# An Enumerator can also be used as an external iterator.
# For example, Enumerator#next returns the next value of the iterator
# or raises StopIteration if the Enumerator is at the end.
#
#       e = [1,2,3].each   # returns an enumerator object.
#       puts e.next   # => 1
#       puts e.next   # => 2
#       puts e.next   # => 3
#       puts e.next   # raises StopIteration
#
# You can use this to implement an internal iterator as follows:
#
#       def ext_each(e)
#         while true
#           begin
#             vs = e.next_values
#           rescue StopIteration
#             return $!.result
#           end
#           y = yield(*vs)
#           e.feed y
#         end
#       end
#
#       o = Object.new
#
#       def o.each
#         puts yield
#         puts yield(1)
#         puts yield(1, 2)
#         3
#       end
#
#       # use o.each as an internal iterator directly.
#       puts o.each {|*x| puts x; [:b, *x] }
#       # => [], [:b], [1], [:b, 1], [1, 2], [:b, 1, 2], 3
#
#       # convert o.each to an external iterator for
#       # implementing an internal iterator.
#       puts ext_each(o.to_enum) {|*x| puts x; [:b, *x] }
#       # => [], [:b], [1], [:b, 1], [1, 2], [:b, 1, 2], 3
#
class Enumerator
  include Enumerable

  ##
  # @overload initialize(size = nil, &block)
  # @overload initialize(obj, method = :each, *args)
  #
  # Creates a new Enumerator object, which can be used as an
  # Enumerable.
  #
  # In the first form, iteration is defined by the given block, in
  # which a "yielder" object, given as block parameter, can be used to
  # yield a value by calling the +yield+ method (aliased as +<<+):
  #
  #     fib = Enumerator.new do |y|
  #       a = b = 1
  #       loop do
  #         y << a
  #         a, b = b, a + b
  #       end
  #     end
  #
  #     p fib.take(10) # => [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]
  #
  def initialize(obj=nil, meth=:each, *args, &block)
    if block
      obj = Generator.new(&block)
    else
      raise ArgumentError unless obj
    end
    if @obj and !self.respond_to?(meth)
      raise NoMethodError, "undefined method #{meth}"
    end

    @obj = obj
    @meth = meth
    @args = args.dup
    @fib = nil
    @dst = nil
    @lookahead = nil
    @feedvalue = nil
    @stop_exc = false
  end
  attr_accessor :obj, :meth, :args, :fib
  private :obj, :meth, :args, :fib

  def initialize_copy(obj)
    raise TypeError, "can't copy type #{obj.class}" unless obj.kind_of? Enumerator
    raise TypeError, "can't copy execution context" if obj.fib
    @obj = obj.obj
    @meth = obj.meth
    @args = obj.args
    @fib = nil
    @lookahead = nil
    @feedvalue = nil
    self
  end

  ##
  # call-seq:
  #   e.with_index(offset = 0) {|(*args), idx| ... }
  #   e.with_index(offset = 0)
  #
  # Iterates the given block for each element with an index, which
  # starts from +offset+.  If no block is given, returns a new Enumerator
  # that includes the index, starting from +offset+
  #
  # +offset+:: the starting index to use
  #
  def with_index(offset=0, &block)
    return to_enum :with_index, offset unless block

    offset = if offset.nil?
      0
    elsif offset.respond_to?(:to_int)
      offset.to_int
    else
      raise TypeError, "no implicit conversion of #{offset.class} into Integer"
    end

    n = offset - 1
    enumerator_block_call do |*i|
      n += 1
      block.call i.__svalue, n
    end
  end

  ##
  # call-seq:
  #   e.each_with_index {|(*args), idx| ... }
  #   e.each_with_index
  #
  # Same as Enumerator#with_index(0), i.e. there is no starting offset.
  #
  # If no block is given, a new Enumerator is returned that includes the index.
  #
  def each_with_index(&block)
    with_index(0, &block)
  end

  ##
  # call-seq:
  #   e.each_with_object(obj) {|(*args), obj| ... }
  #   e.each_with_object(obj)
  #   e.with_object(obj) {|(*args), obj| ... }
  #   e.with_object(obj)
  #
  # Iterates the given block for each element with an arbitrary object, +obj+,
  # and returns +obj+
  #
  # If no block is given, returns a new Enumerator.
  #
  # @example
  #   to_three = Enumerator.new do |y|
  #     3.times do |x|
  #       y << x
  #     end
  #   end
  #
  #   to_three_with_string = to_three.with_object("foo")
  #   to_three_with_string.each do |x,string|
  #     puts "#{string}: #{x}"
  #   end
  #
  #   # => foo:0
  #   # => foo:1
  #   # => foo:2
  #
  def with_object(object, &block)
    return to_enum(:with_object, object) unless block

    enumerator_block_call do |i|
      block.call [i,object]
    end
    object
  end

  def inspect
    return "#<#{self.class}: uninitialized>" unless @obj

    if @args && @args.size > 0
      args = @args.join(", ")
      "#<#{self.class}: #{@obj}:#{@meth}(#{args})>"
    else
      "#<#{self.class}: #{@obj}:#{@meth}>"
    end
  end

  ##
  # call-seq:
  #   enum.each { |elm| block }                    -> obj
  #   enum.each                                    -> enum
  #   enum.each(*appending_args) { |elm| block }   -> obj
  #   enum.each(*appending_args)                   -> an_enumerator
  #
  # Iterates over the block according to how this Enumerator was constructed.
  # If no block and no arguments are given, returns self.
  #
  # === Examples
  #
  #   "Hello, world!".scan(/\w+/)                     #=> ["Hello", "world"]
  #   "Hello, world!".to_enum(:scan, /\w+/).to_a      #=> ["Hello", "world"]
  #   "Hello, world!".to_enum(:scan).each(/\w+/).to_a #=> ["Hello", "world"]
  #
  #   obj = Object.new
  #
  #   def obj.each_arg(a, b=:b, *rest)
  #     yield a
  #     yield b
  #     yield rest
  #     :method_returned
  #   end
  #
  #   enum = obj.to_enum :each_arg, :a, :x
  #
  #   enum.each.to_a                  #=> [:a, :x, []]
  #   enum.each.equal?(enum)          #=> true
  #   enum.each { |elm| elm }         #=> :method_returned
  #
  #   enum.each(:y, :z).to_a          #=> [:a, :x, [:y, :z]]
  #   enum.each(:y, :z).equal?(enum)  #=> false
  #   enum.each(:y, :z) { |elm| elm } #=> :method_returned
  #
  def each(*argv, &block)
    obj = self
    if 0 < argv.length
      obj = self.dup
      args = obj.args
      if !args.empty?
        args = args.dup
        args.concat argv
      else
        args = argv.dup
      end
      obj.args = args
    end
    return obj unless block
    enumerator_block_call(&block)
  end

  def enumerator_block_call(&block)
    @obj.__send__ @meth, *@args, &block
  end
  private :enumerator_block_call

  ##
  # call-seq:
  #   e.next   -> object
  #
  # Returns the next object in the enumerator, and move the internal position
  # forward.  When the position reached at the end, StopIteration is raised.
  #
  # === Example
  #
  #   a = [1,2,3]
  #   e = a.to_enum
  #   p e.next   #=> 1
  #   p e.next   #=> 2
  #   p e.next   #=> 3
  #   p e.next   #raises StopIteration
  #
  # Note that enumeration sequence by +next+ does not affect other non-external
  # enumeration methods, unless the underlying iteration methods itself has
  # side-effect
  #
  def next
    next_values.__svalue
  end

  ##
  # call-seq:
  #   e.next_values   -> array
  #
  # Returns the next object as an array in the enumerator, and move the
  # internal position forward.  When the position reached at the end,
  # StopIteration is raised.
  #
  # This method can be used to distinguish <code>yield</code> and <code>yield
  # nil</code>.
  #
  # === Example
  #
  #   o = Object.new
  #   def o.each
  #     yield
  #     yield 1
  #     yield 1, 2
  #     yield nil
  #     yield [1, 2]
  #   end
  #   e = o.to_enum
  #   p e.next_values
  #   p e.next_values
  #   p e.next_values
  #   p e.next_values
  #   p e.next_values
  #   e = o.to_enum
  #   p e.next
  #   p e.next
  #   p e.next
  #   p e.next
  #   p e.next
  #
  #   ## yield args       next_values      next
  #   #  yield            []               nil
  #   #  yield 1          [1]              1
  #   #  yield 1, 2       [1, 2]           [1, 2]
  #   #  yield nil        [nil]            nil
  #   #  yield [1, 2]     [[1, 2]]         [1, 2]
  #
  # Note that +next_values+ does not affect other non-external enumeration
  # methods unless underlying iteration method itself has side-effect
  #
  def next_values
    if @lookahead
      vs = @lookahead
      @lookahead = nil
      return vs
    end
    raise @stop_exc if @stop_exc

    curr = Fiber.current

    if !@fib || !@fib.alive?
      @dst = curr
      @fib = Fiber.new do
        result = each do |*args|
          feedvalue = nil
          Fiber.yield args
          if @feedvalue
            feedvalue = @feedvalue
            @feedvalue = nil
          end
          feedvalue
        end
        @stop_exc = StopIteration.new "iteration reached an end"
        @stop_exc.result = result
        Fiber.yield nil
      end
      @lookahead = nil
    end

    vs = @fib.resume curr
    if @stop_exc
      @fib = nil
      @dst = nil
      @lookahead = nil
      @feedvalue = nil
      raise @stop_exc
    end
    vs
  end

  ##
  # call-seq:
  #   e.peek   -> object
  #
  # Returns the next object in the enumerator, but doesn't move the internal
  # position forward.  If the position is already at the end, StopIteration
  # is raised.
  #
  # === Example
  #
  #   a = [1,2,3]
  #   e = a.to_enum
  #   p e.next   #=> 1
  #   p e.peek   #=> 2
  #   p e.peek   #=> 2
  #   p e.peek   #=> 2
  #   p e.next   #=> 2
  #   p e.next   #=> 3
  #   p e.next   #raises StopIteration
  #
  def peek
    peek_values.__svalue
  end

  ##
  # call-seq:
  #   e.peek_values   -> array
  #
  # Returns the next object as an array, similar to Enumerator#next_values, but
  # doesn't move the internal position forward.  If the position is already at
  # the end, StopIteration is raised.
  #
  # === Example
  #
  #   o = Object.new
  #   def o.each
  #     yield
  #     yield 1
  #     yield 1, 2
  #   end
  #   e = o.to_enum
  #   p e.peek_values    #=> []
  #   e.next
  #   p e.peek_values    #=> [1]
  #   p e.peek_values    #=> [1]
  #   e.next
  #   p e.peek_values    #=> [1, 2]
  #   e.next
  #   p e.peek_values    # raises StopIteration
  #
  def peek_values
    if @lookahead.nil?
      @lookahead = next_values
    end
    @lookahead.dup
  end

  ##
  # call-seq:
  #   e.rewind   -> e
  #
  # Rewinds the enumeration sequence to the beginning.
  #
  # If the enclosed object responds to a "rewind" method, it is called.
  #
  def rewind
    @obj.rewind if @obj.respond_to? :rewind
    @fib = nil
    @dst = nil
    @lookahead = nil
    @feedvalue = nil
    @stop_exc = false
    self
  end

  ##
  # call-seq:
  #   e.feed obj   -> nil
  #
  # Sets the value to be returned by the next yield inside +e+.
  #
  # If the value is not set, the yield returns nil.
  #
  # This value is cleared after being yielded.
  #
  #   # Array#map passes the array's elements to "yield" and collects the
  #   # results of "yield" as an array.
  #   # Following example shows that "next" returns the passed elements and
  #   # values passed to "feed" are collected as an array which can be
  #   # obtained by StopIteration#result.
  #   e = [1,2,3].map
  #   p e.next           #=> 1
  #   e.feed "a"
  #   p e.next           #=> 2
  #   e.feed "b"
  #   p e.next           #=> 3
  #   e.feed "c"
  #   begin
  #     e.next
  #   rescue StopIteration
  #     p $!.result      #=> ["a", "b", "c"]
  #   end
  #
  #   o = Object.new
  #   def o.each
  #     x = yield         # (2) blocks
  #     p x               # (5) => "foo"
  #     x = yield         # (6) blocks
  #     p x               # (8) => nil
  #     x = yield         # (9) blocks
  #     p x               # not reached w/o another e.next
  #   end
  #
  #   e = o.to_enum
  #   e.next              # (1)
  #   e.feed "foo"        # (3)
  #   e.next              # (4)
  #   e.next              # (7)
  #                       # (10)
  #
  def feed(value)
    raise TypeError, "feed value already set" if @feedvalue
    @feedvalue = value
    nil
  end

  # just for internal
  class Generator
    include Enumerable
    def initialize(&block)
      raise TypeError, "wrong argument type #{self.class} (expected Proc)" unless block.kind_of? Proc

      @proc = block
    end

    def each(*args, &block)
      args.unshift Yielder.new(&block)
      @proc.call(*args)
    end
  end

  # just for internal
  class Yielder
    def initialize(&block)
      raise LocalJumpError, "no block given" unless block

      @proc = block
    end

    def yield(*args)
      @proc.call(*args)
    end

    def << *args
      self.yield(*args)
      self
    end
  end
end

module Kernel
  ##
  # call-seq:
  #   obj.to_enum(method = :each, *args)                 -> enum
  #   obj.enum_for(method = :each, *args)                -> enum
  #   obj.to_enum(method = :each, *args) {|*args| block} -> enum
  #   obj.enum_for(method = :each, *args){|*args| block} -> enum
  #
  # Creates a new Enumerator which will enumerate by calling +method+ on
  # +obj+, passing +args+ if any.
  #
  # If a block is given, it will be used to calculate the size of
  # the enumerator without the need to iterate it (see Enumerator#size).
  #
  # === Examples
  #
  #   str = "xyz"
  #
  #   enum = str.enum_for(:each_byte)
  #   enum.each { |b| puts b }
  #   # => 120
  #   # => 121
  #   # => 122
  #
  #   # protect an array from being modified by some_method
  #   a = [1, 2, 3]
  #   some_method(a.to_enum)
  #
  # It is typical to call to_enum when defining methods for
  # a generic Enumerable, in case no block is passed.
  #
  # Here is such an example, with parameter passing and a sizing block:
  #
  #     module Enumerable
  #       # a generic method to repeat the values of any enumerable
  #       def repeat(n)
  #         raise ArgumentError, "#{n} is negative!" if n < 0
  #         unless block_given?
  #           return to_enum(__method__, n) do # __method__ is :repeat here
  #             sz = size     # Call size and multiply by n...
  #             sz * n if sz  # but return nil if size itself is nil
  #           end
  #         end
  #         each do |*val|
  #           n.times { yield *val }
  #         end
  #       end
  #     end
  #
  #     %i[hello world].repeat(2) { |w| puts w }
  #       # => Prints 'hello', 'hello', 'world', 'world'
  #     enum = (1..14).repeat(3)
  #       # => returns an Enumerator when called without a block
  #     enum.first(4) # => [1, 1, 1, 2]
  #
  def to_enum(meth=:each, *args)
    Enumerator.new self, meth, *args
  end
  alias enum_for to_enum
end

module Enumerable
  # use Enumerator to use infinite sequence
  def zip(*args, &block)
    args = args.map do |a|
      if a.respond_to?(:to_ary)
        a.to_ary.to_enum(:each)
      elsif a.respond_to?(:each)
        a.to_enum(:each)
      else
        raise TypeError, "wrong argument type #{a.class} (must respond to :each)"
      end
    end

    result = block ? nil : []

    each do |*val|
      tmp = [val.__svalue]
      args.each do |arg|
        v = if arg.nil?
          nil
        else
          begin
            arg.next
          rescue StopIteration
            nil
          end
        end
        tmp.push(v)
      end
      if result.nil?
        block.call(tmp)
      else
        result.push(tmp)
      end
    end

    result
  end
end
