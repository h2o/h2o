##
# Enumerable
#
# The <code>Enumerable</code> mixin provides collection classes with
# several traversal and searching methods, and with the ability to
# sort. The class must provide a method `each`, which
# yields successive members of the collection. If
# {Enumerable#max}, {#min}, or
# {#sort} is used, the objects in the collection must also
# implement a meaningful `<=>` operator, as these methods
# rely on an ordering between members of the collection.
#
# ISO 15.3.2
module Enumerable

  NONE = Object.new

  ##
  # Call the given block for each element
  # which is yield by +each+. Return false
  # if one block value is false. Otherwise
  # return true. If no block is given and
  # +self+ is false return false.
  #
  # ISO 15.3.2.2.1
  def all?(&block)
    if block
      self.each{|*val| return false unless block.call(*val)}
    else
      self.each{|*val| return false unless val.__svalue}
    end
    true
  end

  ##
  # Call the given block for each element
  # which is yield by +each+. Return true
  # if one block value is true. Otherwise
  # return false. If no block is given and
  # +self+ is true object return true.
  #
  # ISO 15.3.2.2.2
  def any?(&block)
    if block
      self.each{|*val| return true if block.call(*val)}
    else
      self.each{|*val| return true if val.__svalue}
    end
    false
  end

  ##
  # Call the given block for each element
  # which is yield by +each+. Append all
  # values of each block together and
  # return this value.
  #
  # ISO 15.3.2.2.3
  def collect(&block)
    return to_enum :collect unless block

    ary = []
    self.each{|*val| ary.push(block.call(*val))}
    ary
  end

  ##
  # Return the first element for which
  # value from the block is true. If no
  # object matches, calls +ifnone+ and
  # returns its result. Otherwise returns
  # +nil+.
  #
  # ISO 15.3.2.2.4
  def detect(ifnone=nil, &block)
    return to_enum :detect, ifnone unless block

    self.each{|*val|
      if block.call(*val)
        return val.__svalue
      end
    }
    ifnone.call unless ifnone.nil?
  end

  ##
  # Call the given block for each element
  # which is yield by +each+. Pass an
  # index to the block which starts at 0
  # and increase by 1 for each element.
  #
  # ISO 15.3.2.2.5
  def each_with_index(&block)
    return to_enum :each_with_index unless block

    i = 0
    self.each{|*val|
      block.call(val.__svalue, i)
      i += 1
    }
    self
  end

  ##
  # Return an array of all elements which
  # are yield by +each+.
  #
  # ISO 15.3.2.2.6
  def entries
    ary = []
    self.each{|*val|
      # __svalue is an internal method
      ary.push val.__svalue
    }
    ary
  end

  ##
  # Alias for find
  #
  # ISO 15.3.2.2.7
  alias find detect

  ##
  # Call the given block for each element
  # which is yield by +each+. Return an array
  # which contains all elements whose block
  # value was true.
  #
  # ISO 15.3.2.2.8
  def find_all(&block)
    return to_enum :find_all unless block

    ary = []
    self.each{|*val|
      ary.push(val.__svalue) if block.call(*val)
    }
    ary
  end

  ##
  # Call the given block for each element
  # which is yield by +each+ and which return
  # value was true when invoking === with
  # +pattern+. Return an array with all
  # elements or the respective block values.
  #
  # ISO 15.3.2.2.9
  def grep(pattern, &block)
    ary = []
    self.each{|*val|
      sv = val.__svalue
      if pattern === sv
        ary.push((block)? block.call(*val): sv)
      end
    }
    ary
  end

  ##
  # Return true if at least one element which
  # is yield by +each+ returns a true value
  # by invoking == with +obj+. Otherwise return
  # false.
  #
  # ISO 15.3.2.2.10
  def include?(obj)
    self.each{|*val|
      return true if val.__svalue == obj
    }
    false
  end

  ##
  # Call the given block for each element
  # which is yield by +each+. Return value
  # is the sum of all block values. Pass
  # to each block the current sum and the
  # current element.
  #
  # ISO 15.3.2.2.11
  def inject(*args, &block)
    raise ArgumentError, "too many arguments" if args.size > 2
    if Symbol === args[-1]
      sym = args[-1]
      block = ->(x,y){x.__send__(sym,y)}
      args.pop
    end
    if args.empty?
      flag = true  # no initial argument
      result = nil
    else
      flag = false
      result = args[0]
    end
    self.each{|*val|
      val = val.__svalue
      if flag
        # push first element as initial
        flag = false
        result = val
      else
        result = block.call(result, val)
      end
    }
    result
  end
  alias reduce inject

  ##
  # Alias for collect
  #
  # ISO 15.3.2.2.12
  alias map collect

  ##
  # Return the maximum value of all elements
  # yield by +each+. If no block is given <=>
  # will be invoked to define this value. If
  # a block is given it will be used instead.
  #
  # ISO 15.3.2.2.13
  def max(&block)
    flag = true  # 1st element?
    result = nil
    self.each{|*val|
      val = val.__svalue
      if flag
        # 1st element
        result = val
        flag = false
      else
        if block
          result = val if block.call(val, result) > 0
        else
          result = val if (val <=> result) > 0
        end
      end
    }
    result
  end

  ##
  # Return the minimum value of all elements
  # yield by +each+. If no block is given <=>
  # will be invoked to define this value. If
  # a block is given it will be used instead.
  #
  # ISO 15.3.2.2.14
  def min(&block)
    flag = true  # 1st element?
    result = nil
    self.each{|*val|
      val = val.__svalue
      if flag
        # 1st element
        result = val
        flag = false
      else
        if block
          result = val if block.call(val, result) < 0
        else
          result = val if (val <=> result) < 0
        end
      end
    }
    result
  end

  ##
  # Alias for include?
  #
  # ISO 15.3.2.2.15
  alias member? include?

  ##
  # Call the given block for each element
  # which is yield by +each+. Return an
  # array which contains two arrays. The
  # first array contains all elements
  # whose block value was true. The second
  # array contains all elements whose
  # block value was false.
  #
  # ISO 15.3.2.2.16
  def partition(&block)
    return to_enum :partition unless block

    ary_T = []
    ary_F = []
    self.each{|*val|
      if block.call(*val)
        ary_T.push(val.__svalue)
      else
        ary_F.push(val.__svalue)
      end
    }
    [ary_T, ary_F]
  end

  ##
  # Call the given block for each element
  # which is yield by +each+. Return an
  # array which contains only the elements
  # whose block value was false.
  #
  # ISO 15.3.2.2.17
  def reject(&block)
    return to_enum :reject unless block

    ary = []
    self.each{|*val|
      ary.push(val.__svalue) unless block.call(*val)
    }
    ary
  end

  ##
  # Alias for find_all.
  #
  # ISO 15.3.2.2.18
  alias select find_all

  ##
  # Return a sorted array of all elements
  # which are yield by +each+. If no block
  # is given <=> will be invoked on each
  # element to define the order. Otherwise
  # the given block will be used for
  # sorting.
  #
  # ISO 15.3.2.2.19
  def sort(&block)
    self.map{|*val| val.__svalue}.sort(&block)
  end

  ##
  # Alias for entries.
  #
  # ISO 15.3.2.2.20
  alias to_a entries

  # redefine #hash 15.3.1.3.15
  def hash
    h = 12347
    i = 0
    self.each do |e|
      h = __update_hash(h, i, e.hash)
      i += 1
    end
    h
  end
end
