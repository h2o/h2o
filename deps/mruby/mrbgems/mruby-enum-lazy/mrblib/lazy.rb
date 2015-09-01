# = Enumerable#lazy implementation
#
# Enumerable#lazy returns an instance of Enumerable::Lazy.
# You can use it just like as normal Enumerable object,
# except these methods act as 'lazy':
#
#   - map       collect
#   - select    find_all
#   - reject
#   - grep
#   - drop
#   - drop_while
#   - take_while
#   - flat_map  collect_concat
#   - zip
#
# == Acknowledgements
#
#   Based on https://github.com/yhara/enumerable-lazy
#   Inspired by https://github.com/antimon2/enumerable_lz
#   http://jp.rubyist.net/magazine/?0034-Enumerable_lz (ja)

module Enumerable
  def lazy
    Lazy.new(self)
  end

  class Lazy < Enumerator
    def initialize(obj, &block)
      super(){|yielder|
        begin
          obj.each{|x|
            if block
              block.call(yielder, x)
            else
              yielder << x
            end
          }
        rescue StopIteration
        end
      }
    end

    def map(&block)
      Lazy.new(self){|yielder, val|
        yielder << block.call(val)
      }
    end
    alias collect map

    def select(&block)
      Lazy.new(self){|yielder, val|
        if block.call(val)
          yielder << val
        end
      }
    end
    alias find_all select

    def reject(&block)
      Lazy.new(self){|yielder, val|
        if not block.call(val)
          yielder << val
        end
      }
    end

    def grep(pattern)
      Lazy.new(self){|yielder, val|
        if pattern === val
          yielder << val
        end
      }
    end

    def drop(n)
      dropped = 0
      Lazy.new(self){|yielder, val|
        if dropped < n
          dropped += 1
        else
          yielder << val
        end
      }
    end

    def drop_while(&block)
      dropping = true
      Lazy.new(self){|yielder, val|
        if dropping
          if not block.call(val)
            yielder << val
            dropping = false
          end
        else
          yielder << val
        end
      }
    end

    def take(n)
      if n == 0
        return Lazy.new(self){raise StopIteration}
      end
      taken = 0
      Lazy.new(self){|yielder, val|
        yielder << val
        taken += 1
        if taken >= n
          raise StopIteration
        end
      }
    end

    def take_while(&block)
      Lazy.new(self){|yielder, val|
        if block.call(val)
          yielder << val
        else
          raise StopIteration
        end
      }
    end

    def flat_map(&block)
      Lazy.new(self){|yielder, val|
        ary = block.call(val)
        # TODO: check ary is an Array
        ary.each{|x|
          yielder << x
        }
      }
    end
    alias collect_concat flat_map

    def zip(*args, &block)
      enums = [self] + args
      Lazy.new(self){|yielder, val|
        ary = enums.map{|e| e.next}
        if block
          yielder << block.call(ary)
        else
          yielder << ary
        end
      }
    end

    alias force to_a
  end
end
