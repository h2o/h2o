class Range
  ##
  # call-seq:
  #    rng.first    -> obj
  #    rng.first(n) -> an_array
  #
  # Returns the first object in the range, or an array of the first +n+
  # elements.
  #
  #   (10..20).first     #=> 10
  #   (10..20).first(3)  #=> [10, 11, 12]
  #
  def first(*args)
    return self.begin if args.empty?

    raise ArgumentError, "wrong number of arguments (given #{args.length}, expected 1)" unless args.length == 1
    nv = args[0]
    n = nv.__to_int
    raise ArgumentError, "negative array size (or size too big)" unless 0 <= n
    ary = []
    each do |i|
      break if n <= 0
      ary.push(i)
      n -= 1
    end
    ary
  end

  def max(&block)
    val = self.first
    last = self.last
    return super if block

    # fast path for numerics
    if val.kind_of?(Numeric) && last.kind_of?(Numeric)
      raise TypeError if exclude_end? && !last.kind_of?(Fixnum)
      return nil if val > last
      return nil if val == last && exclude_end?

      max = last
      max -= 1 if exclude_end?
      return max
    end

    # delegate to Enumerable
    super
  end

  def min(&block)
    val = self.first
    last = self.last
    return super if block

    # fast path for numerics
    if val.kind_of?(Numeric) && last.kind_of?(Numeric)
      return nil if val > last
      return nil if val == last && exclude_end?

      min = val
      return min
    end

    # delegate to Enumerable
    super
  end
end
