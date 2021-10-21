##
# chain.rb Enumerator::Chain class
# See Copyright Notice in mruby.h

module Enumerable
  def chain(*args)
    Enumerator::Chain.new(self, *args)
  end

  def +(other)
    Enumerator::Chain.new(self, other)
  end
end

class Enumerator
  class Chain
    include Enumerable

    def initialize(*args)
      @enums = args
    end

    def initialize_copy(orig)
      @enums = orig.__copy_enums
    end

    def each(&block)
      return to_enum unless block_given?

      @enums.each { |e| e.each(&block) }

      self
    end

    def size
      @enums.reduce(0) do |a, e|
        return nil unless e.respond_to?(:size)
        a + e.size
      end
    end

    def rewind
      @enums.reverse_each do |e|
        e.rewind if e.respond_to?(:rewind)
      end

      self
    end

    def inspect
      "#<#{self.class}: #{@enums.inspect}>"
    end

    def __copy_enums
      @enums.each_with_object([]) do |e, a|
        a << e.clone
      end
    end
  end
end
