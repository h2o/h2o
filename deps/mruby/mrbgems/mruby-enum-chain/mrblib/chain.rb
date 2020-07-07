##
# chain.rb Enumerator::Chain class
# See Copyright Notice in mruby.h

module Enumerable
  def chain(*args)
    Enumerator::Chain.new(self, *args)
  end
end

class Enumerator
  def +(other)
    Chain.new(self, other)
  end

  class Chain
    include Enumerable

    def initialize(*args)
      @enums = args.freeze
      @pos = -1
    end

    def each(&block)
      return to_enum unless block

      i = 0
      while i < @enums.size
        @pos = i
        @enums[i].each(&block)
        i += 1
      end

      self
    end

    def size
      @enums.reduce(0) do |a, e|
        return nil unless e.respond_to?(:size)
        a + e.size
      end
    end

    def rewind
      while 0 <= @pos && @pos < @enums.size
        e = @enums[@pos]
        e.rewind if e.respond_to?(:rewind)
        @pos -= 1
      end

      self
    end

    def +(other)
      self.class.new(self, other)
    end

    def inspect
      "#<#{self.class}: #{@enums.inspect}>"
    end
  end
end
