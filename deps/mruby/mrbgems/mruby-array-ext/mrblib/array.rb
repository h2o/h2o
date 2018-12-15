class Array
  ##
  # call-seq:
  #    Array.try_convert(obj) -> array or nil
  #
  # Tries to convert +obj+ into an array, using +to_ary+ method.
  # converted array or +nil+ if +obj+ cannot be converted for any reason.
  # This method can be used to check if an argument is an array.
  #
  #    Array.try_convert([1])   #=> [1]
  #    Array.try_convert("1")   #=> nil
  #
  #    if tmp = Array.try_convert(arg)
  #      # the argument is an array
  #    elsif tmp = String.try_convert(arg)
  #      # the argument is a string
  #    end
  #
  def self.try_convert(obj)
    if obj.respond_to?(:to_ary)
      obj.to_ary
    else
      nil
    end
  end

  ##
  # call-seq:
  #    ary.uniq!                -> ary or nil
  #    ary.uniq! { |item| ... } -> ary or nil
  #
  # Removes duplicate elements from +self+.
  # Returns <code>nil</code> if no changes are made (that is, no
  # duplicates are found).
  #
  #    a = [ "a", "a", "b", "b", "c" ]
  #    a.uniq!   #=> ["a", "b", "c"]
  #    b = [ "a", "b", "c" ]
  #    b.uniq!   #=> nil
  #    c = [["student","sam"], ["student","george"], ["teacher","matz"]]
  #    c.uniq! { |s| s.first } # => [["student", "sam"], ["teacher", "matz"]]
  #
  def uniq!(&block)
    ary = self.dup
    result = []
    if block
      hash = {}
      while ary.size > 0
        val = ary.shift
        key = block.call(val)
        hash[key] = val unless hash.has_key?(key)
      end
      hash.each_value do |value|
        result << value
      end
    else
      while ary.size > 0
        result << ary.shift
        ary.delete(result.last)
      end
    end
    if result.size == self.size
      nil
    else
      self.replace(result)
    end
  end

  ##
  # call-seq:
  #    ary.uniq                -> new_ary
  #    ary.uniq { |item| ... } -> new_ary
  #
  # Returns a new array by removing duplicate values in +self+.
  #
  #    a = [ "a", "a", "b", "b", "c" ]
  #    a.uniq   #=> ["a", "b", "c"]
  #
  #    b = [["student","sam"], ["student","george"], ["teacher","matz"]]
  #    b.uniq { |s| s.first } # => [["student", "sam"], ["teacher", "matz"]]
  #
  def uniq(&block)
    ary = self.dup
    ary.uniq!(&block)
    ary
  end

  ##
  # call-seq:
  #    ary - other_ary    -> new_ary
  #
  # Array Difference---Returns a new array that is a copy of
  # the original array, removing any items that also appear in
  # <i>other_ary</i>. (If you need set-like behavior, see the
  # library class Set.)
  #
  #    [ 1, 1, 2, 2, 3, 3, 4, 5 ] - [ 1, 2, 4 ]  #=>  [ 3, 3, 5 ]
  #
  def -(elem)
    raise TypeError, "can't convert #{elem.class} into Array" unless elem.class == Array

    hash = {}
    array = []
    idx = 0
    len = elem.size
    while idx < len
      hash[elem[idx]] = true
      idx += 1
    end
    idx = 0
    len = size
    while idx < len
      v = self[idx]
      array << v unless hash[v]
      idx += 1
    end
    array
  end

  ##
  # call-seq:
  #    ary | other_ary     -> new_ary
  #
  # Set Union---Returns a new array by joining this array with
  # <i>other_ary</i>, removing duplicates.
  #
  #    [ "a", "b", "c" ] | [ "c", "d", "a" ]
  #           #=> [ "a", "b", "c", "d" ]
  #
  def |(elem)
    raise TypeError, "can't convert #{elem.class} into Array" unless elem.class == Array

    ary = self + elem
    ary.uniq! or ary
  end

  ##
  # call-seq:
  #    ary & other_ary      -> new_ary
  #
  # Set Intersection---Returns a new array
  # containing elements common to the two arrays, with no duplicates.
  #
  #    [ 1, 1, 3, 5 ] & [ 1, 2, 3 ]   #=> [ 1, 3 ]
  #
  def &(elem)
    raise TypeError, "can't convert #{elem.class} into Array" unless elem.class == Array

    hash = {}
    array = []
    idx = 0
    len = elem.size
    while idx < len
      hash[elem[idx]] = true
      idx += 1
    end
    idx = 0
    len = size
    while idx < len
      v = self[idx]
      if hash[v]
        array << v
        hash.delete v
      end
      idx += 1
    end
    array
  end

  ##
  # call-seq:
  #    ary.flatten -> new_ary
  #    ary.flatten(level) -> new_ary
  #
  # Returns a new array that is a one-dimensional flattening of this
  # array (recursively). That is, for every element that is an array,
  # extract its elements into the new array.  If the optional
  # <i>level</i> argument determines the level of recursion to flatten.
  #
  #    s = [ 1, 2, 3 ]           #=> [1, 2, 3]
  #    t = [ 4, 5, 6, [7, 8] ]   #=> [4, 5, 6, [7, 8]]
  #    a = [ s, t, 9, 10 ]       #=> [[1, 2, 3], [4, 5, 6, [7, 8]], 9, 10]
  #    a.flatten                 #=> [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
  #    a = [ 1, 2, [3, [4, 5] ] ]
  #    a.flatten(1)              #=> [1, 2, 3, [4, 5]]
  #
  def flatten(depth=nil)
    res = dup
    res.flatten! depth
    res
  end

  ##
  # call-seq:
  #    ary.flatten!        -> ary or nil
  #    ary.flatten!(level) -> array or nil
  #
  # Flattens +self+ in place.
  # Returns <code>nil</code> if no modifications were made (i.e.,
  # <i>ary</i> contains no subarrays.)  If the optional <i>level</i>
  # argument determines the level of recursion to flatten.
  #
  #    a = [ 1, 2, [3, [4, 5] ] ]
  #    a.flatten!   #=> [1, 2, 3, 4, 5]
  #    a.flatten!   #=> nil
  #    a            #=> [1, 2, 3, 4, 5]
  #    a = [ 1, 2, [3, [4, 5] ] ]
  #    a.flatten!(1) #=> [1, 2, 3, [4, 5]]
  #
  def flatten!(depth=nil)
    modified = false
    ar = []
    idx = 0
    len = size
    while idx < len
      e = self[idx]
      if e.is_a?(Array) && (depth.nil? || depth > 0)
        ar += e.flatten(depth.nil? ? nil : depth - 1)
        modified = true
      else
        ar << e
      end
      idx += 1
    end
    if modified
      self.replace(ar)
    else
      nil
    end
  end

  ##
  # call-seq:
  #    ary.compact     -> new_ary
  #
  # Returns a copy of +self+ with all +nil+ elements removed.
  #
  #    [ "a", nil, "b", nil, "c", nil ].compact
  #                      #=> [ "a", "b", "c" ]
  #
  def compact
    result = self.dup
    result.compact!
    result
  end

  ##
  # call-seq:
  #    ary.compact!    -> ary  or  nil
  #
  # Removes +nil+ elements from the array.
  # Returns +nil+ if no changes were made, otherwise returns
  # <i>ary</i>.
  #
  #    [ "a", nil, "b", nil, "c" ].compact! #=> [ "a", "b", "c" ]
  #    [ "a", "b", "c" ].compact!           #=> nil
  #
  def compact!
    result = self.select { |e| !e.nil? }
    if result.size == self.size
      nil
    else
      self.replace(result)
    end
  end

  # for efficiency
  def reverse_each(&block)
    return to_enum :reverse_each unless block

    i = self.size - 1
    while i>=0
      block.call(self[i])
      i -= 1
    end
    self
  end

  NONE=Object.new
  ##
  #  call-seq:
  #     ary.fetch(index)                    -> obj
  #     ary.fetch(index, default)           -> obj
  #     ary.fetch(index) { |index| block }  -> obj
  #
  #  Tries to return the element at position +index+, but throws an IndexError
  #  exception if the referenced +index+ lies outside of the array bounds.  This
  #  error can be prevented by supplying a second argument, which will act as a
  #  +default+ value.
  #
  #  Alternatively, if a block is given it will only be executed when an
  #  invalid +index+ is referenced.
  #
  #  Negative values of +index+ count from the end of the array.
  #
  #     a = [ 11, 22, 33, 44 ]
  #     a.fetch(1)               #=> 22
  #     a.fetch(-1)              #=> 44
  #     a.fetch(4, 'cat')        #=> "cat"
  #     a.fetch(100) { |i| puts "#{i} is out of bounds" }
  #                              #=> "100 is out of bounds"
  #

  def fetch(n=nil, ifnone=NONE, &block)
    warn "block supersedes default value argument" if !n.nil? && ifnone != NONE && block

    idx = n
    if idx < 0
      idx += size
    end
    if idx < 0 || size <= idx
      return block.call(n) if block
      if ifnone == NONE
        raise IndexError, "index #{n} outside of array bounds: #{-size}...#{size}"
      end
      return ifnone
    end
    self[idx]
  end

  ##
  #  call-seq:
  #     ary.fill(obj)                                 -> ary
  #     ary.fill(obj, start [, length])               -> ary
  #     ary.fill(obj, range )                         -> ary
  #     ary.fill { |index| block }                    -> ary
  #     ary.fill(start [, length] ) { |index| block } -> ary
  #     ary.fill(range) { |index| block }             -> ary
  #
  #  The first three forms set the selected elements of +self+ (which
  #  may be the entire array) to +obj+.
  #
  #  A +start+ of +nil+ is equivalent to zero.
  #
  #  A +length+ of +nil+ is equivalent to the length of the array.
  #
  #  The last three forms fill the array with the value of the given block,
  #  which is passed the absolute index of each element to be filled.
  #
  #  Negative values of +start+ count from the end of the array, where +-1+ is
  #  the last element.
  #
  #     a = [ "a", "b", "c", "d" ]
  #     a.fill("x")              #=> ["x", "x", "x", "x"]
  #     a.fill("w", -1)          #=> ["x", "x", "x", "w"]
  #     a.fill("z", 2, 2)        #=> ["x", "x", "z", "z"]
  #     a.fill("y", 0..1)        #=> ["y", "y", "z", "z"]
  #     a.fill { |i| i*i }       #=> [0, 1, 4, 9]
  #     a.fill(-2) { |i| i*i*i } #=> [0, 1, 8, 27]
  #     a.fill(1, 2) { |i| i+1 } #=> [0, 2, 3, 27]
  #     a.fill(0..1) { |i| i+1 } #=> [1, 2, 3, 27]
  #

  def fill(arg0=nil, arg1=nil, arg2=nil, &block)
    if arg0.nil? && arg1.nil? && arg2.nil? && !block
      raise ArgumentError, "wrong number of arguments (0 for 1..3)"
    end

    beg = len = 0
    ary = []
    if block
      if arg0.nil? && arg1.nil? && arg2.nil?
        # ary.fill { |index| block }                    -> ary
        beg = 0
        len = self.size
      elsif !arg0.nil? && arg0.kind_of?(Range)
        # ary.fill(range) { |index| block }             -> ary
        beg = arg0.begin
        beg += self.size if beg < 0
        len = arg0.end
        len += self.size if len < 0
        len += 1 unless arg0.exclude_end?
      elsif !arg0.nil?
        # ary.fill(start [, length] ) { |index| block } -> ary
        beg = arg0
        beg += self.size if beg < 0
        if arg1.nil?
          len = self.size
        else
          len = arg0 + arg1
        end
      end
    else
      if !arg0.nil? && arg1.nil? && arg2.nil?
        # ary.fill(obj)                                 -> ary
        beg = 0
        len = self.size
      elsif !arg0.nil? && !arg1.nil? && arg1.kind_of?(Range)
        # ary.fill(obj, range )                         -> ary
        beg = arg1.begin
        beg += self.size if beg < 0
        len = arg1.end
        len += self.size if len < 0
        len += 1 unless arg1.exclude_end?
      elsif !arg0.nil? && !arg1.nil?
        # ary.fill(obj, start [, length])               -> ary
        beg = arg1
        beg += self.size if beg < 0
        if arg2.nil?
          len = self.size
        else
          len = beg + arg2
        end
      end
    end

    i = beg
    if block
      while i < len
        self[i] = block.call(i)
        i += 1
      end
    else
      while i < len
        self[i] = arg0
        i += 1
      end
    end
    self
  end

  ##
  #  call-seq:
  #     ary.rotate(count=1)    -> new_ary
  #
  #  Returns a new array by rotating +self+ so that the element at +count+ is
  #  the first element of the new array.
  #
  #  If +count+ is negative then it rotates in the opposite direction, starting
  #  from the end of +self+ where +-1+ is the last element.
  #
  #     a = [ "a", "b", "c", "d" ]
  #     a.rotate         #=> ["b", "c", "d", "a"]
  #     a                #=> ["a", "b", "c", "d"]
  #     a.rotate(2)      #=> ["c", "d", "a", "b"]
  #     a.rotate(-3)     #=> ["b", "c", "d", "a"]

  def rotate(count=1)
    ary = []
    len = self.length

    if len > 0
      idx = (count < 0) ? (len - (~count % len) - 1) : (count % len) # rotate count
      len.times do
        ary << self[idx]
        idx += 1
        idx = 0 if idx > len-1
      end
    end
    ary
  end

  ##
  #  call-seq:
  #     ary.rotate!(count=1)   -> ary
  #
  #  Rotates +self+ in place so that the element at +count+ comes first, and
  #  returns +self+.
  #
  #  If +count+ is negative then it rotates in the opposite direction, starting
  #  from the end of the array where +-1+ is the last element.
  #
  #     a = [ "a", "b", "c", "d" ]
  #     a.rotate!        #=> ["b", "c", "d", "a"]
  #     a                #=> ["b", "c", "d", "a"]
  #     a.rotate!(2)     #=> ["d", "a", "b", "c"]
  #     a.rotate!(-3)    #=> ["a", "b", "c", "d"]

  def rotate!(count=1)
    self.replace(self.rotate(count))
  end

  ##
  #  call-seq:
  #     ary.delete_if { |item| block }  -> ary
  #     ary.delete_if                   -> Enumerator
  #
  #  Deletes every element of +self+ for which block evaluates to +true+.
  #
  #  The array is changed instantly every time the block is called, not after
  #  the iteration is over.
  #
  #  See also Array#reject!
  #
  #  If no block is given, an Enumerator is returned instead.
  #
  #     scores = [ 97, 42, 75 ]
  #     scores.delete_if {|score| score < 80 }   #=> [97]

  def delete_if(&block)
    return to_enum :delete_if unless block

    idx = 0
    while idx < self.size do
      if block.call(self[idx])
        self.delete_at(idx)
      else
        idx += 1
      end
    end
    self
  end

  ##
  #  call-seq:
  #     ary.reject! { |item| block }  -> ary or nil
  #     ary.reject!                   -> Enumerator
  #
  #  Equivalent to Array#delete_if, deleting elements from +self+ for which the
  #  block evaluates to +true+, but returns +nil+ if no changes were made.
  #
  #  The array is changed instantly every time the block is called, not after
  #  the iteration is over.
  #
  #  See also Enumerable#reject and Array#delete_if.
  #
  #  If no block is given, an Enumerator is returned instead.

  def reject!(&block)
    return to_enum :reject! unless block

    len = self.size
    idx = 0
    while idx < self.size do
      if block.call(self[idx])
        self.delete_at(idx)
      else
        idx += 1
      end
    end
    if self.size == len
      nil
    else
      self
    end
  end

  ##
  #  call-seq:
  #     ary.insert(index, obj...)  -> ary
  #
  #  Inserts the given values before the element with the given +index+.
  #
  #  Negative indices count backwards from the end of the array, where +-1+ is
  #  the last element.
  #
  #     a = %w{ a b c d }
  #     a.insert(2, 99)         #=> ["a", "b", 99, "c", "d"]
  #     a.insert(-2, 1, 2, 3)   #=> ["a", "b", 99, "c", 1, 2, 3, "d"]

  def insert(idx, *args)
    idx += self.size + 1 if idx < 0
    self[idx, 0] = args
    self
  end

  ##
  #  call-seq:
  #     ary.bsearch {|x| block }  -> elem
  #
  #  By using binary search, finds a value from this array which meets
  #  the given condition in O(log n) where n is the size of the array.
  #
  #  You can use this method in two use cases: a find-minimum mode and
  #  a find-any mode.  In either case, the elements of the array must be
  #  monotone (or sorted) with respect to the block.
  #
  #  In find-minimum mode (this is a good choice for typical use case),
  #  the block must return true or false, and there must be an index i
  #  (0 <= i <= ary.size) so that:
  #
  #  - the block returns false for any element whose index is less than
  #    i, and
  #  - the block returns true for any element whose index is greater
  #    than or equal to i.
  #
  #  This method returns the i-th element.  If i is equal to ary.size,
  #  it returns nil.
  #
  #     ary = [0, 4, 7, 10, 12]
  #     ary.bsearch {|x| x >=   4 } #=> 4
  #     ary.bsearch {|x| x >=   6 } #=> 7
  #     ary.bsearch {|x| x >=  -1 } #=> 0
  #     ary.bsearch {|x| x >= 100 } #=> nil
  #
  #  In find-any mode (this behaves like libc's bsearch(3)), the block
  #  must return a number, and there must be two indices i and j
  #  (0 <= i <= j <= ary.size) so that:
  #
  #  - the block returns a positive number for ary[k] if 0 <= k < i,
  #  - the block returns zero for ary[k] if i <= k < j, and
  #  - the block returns a negative number for ary[k] if
  #    j <= k < ary.size.
  #
  #  Under this condition, this method returns any element whose index
  #  is within i...j.  If i is equal to j (i.e., there is no element
  #  that satisfies the block), this method returns nil.
  #
  #     ary = [0, 4, 7, 10, 12]
  #     # try to find v such that 4 <= v < 8
  #     ary.bsearch {|x| 1 - (x / 4).truncate } #=> 4 or 7
  #     # try to find v such that 8 <= v < 10
  #     ary.bsearch {|x| 4 - (x / 2).truncate } #=> nil
  #
  #  You must not mix the two modes at a time; the block must always
  #  return either true/false, or always return a number.  It is
  #  undefined which value is actually picked up at each iteration.

  def bsearch(&block)
    return to_enum :bsearch unless block

    if idx = bsearch_index(&block)
      self[idx]
    else
      nil
    end
  end

  ##
  #  call-seq:
  #     ary.bsearch_index {|x| block }  -> int or nil
  #
  #  By using binary search, finds an index of a value from this array which
  #  meets the given condition in O(log n) where n is the size of the array.
  #
  #  It supports two modes, depending on the nature of the block and they are
  #  exactly the same as in the case of #bsearch method with the only difference
  #  being that this method returns the index of the element instead of the
  #  element itself. For more details consult the documentation for #bsearch.

  def bsearch_index(&block)
    return to_enum :bsearch_index unless block

    low = 0
    high = size
    satisfied = false

    while low < high
      mid = ((low+high)/2).truncate
      res = block.call self[mid]

      case res
      when 0 # find-any mode: Found!
        return mid
      when Numeric # find-any mode: Continue...
        in_lower_half = res < 0
      when true # find-min mode
        in_lower_half = true
        satisfied = true
      when false, nil # find-min mode
        in_lower_half = false
      else
        raise TypeError, 'invalid block result (must be numeric, true, false or nil)'
      end

      if in_lower_half
        high = mid
      else
        low = mid + 1
      end
    end

    satisfied ? low : nil
  end

  ##
  #  call-seq:
  #     ary.delete_if { |item| block }  -> ary
  #     ary.delete_if                   -> Enumerator
  #
  #  Deletes every element of +self+ for which block evaluates to +true+.
  #
  #  The array is changed instantly every time the block is called, not after
  #  the iteration is over.
  #
  #  See also Array#reject!
  #
  #  If no block is given, an Enumerator is returned instead.
  #
  #     scores = [ 97, 42, 75 ]
  #     scores.delete_if {|score| score < 80 }   #=> [97]

  def delete_if(&block)
    return to_enum :delete_if unless block

    idx = 0
    while idx < self.size do
      if block.call(self[idx])
        self.delete_at(idx)
      else
        idx += 1
      end
    end
    self
  end

  ##
  #  call-seq:
  #     ary.keep_if { |item| block } -> ary
  #     ary.keep_if                  -> Enumerator
  #
  #  Deletes every element of +self+ for which the given block evaluates to
  #  +false+.
  #
  #  See also Array#select!
  #
  #  If no block is given, an Enumerator is returned instead.
  #
  #     a = [1, 2, 3, 4, 5]
  #     a.keep_if { |val| val > 3 } #=> [4, 5]

  def keep_if(&block)
    return to_enum :keep_if unless block

    idx = 0
    len = self.size
    while idx < self.size do
      if block.call(self[idx])
        idx += 1
      else
        self.delete_at(idx)
      end
    end
    self
  end

  ##
  #  call-seq:
  #     ary.select!  {|item| block } -> ary or nil
  #     ary.select!                  -> Enumerator
  #
  #  Invokes the given block passing in successive elements from +self+,
  #  deleting elements for which the block returns a +false+ value.
  #
  #  If changes were made, it will return +self+, otherwise it returns +nil+.
  #
  #  See also Array#keep_if
  #
  #  If no block is given, an Enumerator is returned instead.

  def select!(&block)
    return to_enum :select! unless block

    result = []
    idx = 0
    len = size
    while idx < len
      elem = self[idx]
      result << elem if block.call(elem)
      idx += 1
    end
    return nil if len == result.size
    self.replace(result)
  end

  ##
  #  call-seq:
  #     ary.index(val)            -> int or nil
  #     ary.index {|item| block } ->  int or nil
  #
  #  Returns the _index_ of the first object in +ary+ such that the object is
  #  <code>==</code> to +obj+.
  #
  #  If a block is given instead of an argument, returns the _index_ of the
  #  first object for which the block returns +true+.  Returns +nil+ if no
  #  match is found.
  #
  # ISO 15.2.12.5.14
  def index(val=NONE, &block)
    return to_enum(:find_index, val) if !block && val == NONE

    if block
      idx = 0
      len = size
      while idx < len
        return idx if block.call self[idx]
        idx += 1
      end
    else
      return self.__ary_index(val)
    end
    nil
  end

  ##
  #  call-seq:
  #     ary.to_ary -> ary
  #
  #  Returns +self+.
  #
  def to_ary
    self
  end

  ##
  # call-seq:
  #   ary.dig(idx, ...)                 -> object
  #
  # Extracts the nested value specified by the sequence of <i>idx</i>
  # objects by calling +dig+ at each step, returning +nil+ if any
  # intermediate step is +nil+.
  #
  def dig(idx,*args)
    n = self[idx]
    if args.size > 0
      n&.dig(*args)
    else
      n
    end
  end

  ##
  # call-seq:
  #    ary.permutation { |p| block }          -> ary
  #    ary.permutation                        -> Enumerator
  #    ary.permutation(n) { |p| block }       -> ary
  #    ary.permutation(n)                     -> Enumerator
  #
  # When invoked with a block, yield all permutations of length +n+ of the
  # elements of the array, then return the array itself.
  #
  # If +n+ is not specified, yield all permutations of all elements.
  #
  # The implementation makes no guarantees about the order in which the
  # permutations are yielded.
  #
  # If no block is given, an Enumerator is returned instead.
  #
  # Examples:
  #
  #  a = [1, 2, 3]
  #  a.permutation.to_a    #=> [[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]]
  #  a.permutation(1).to_a #=> [[1],[2],[3]]
  #  a.permutation(2).to_a #=> [[1,2],[1,3],[2,1],[2,3],[3,1],[3,2]]
  #  a.permutation(3).to_a #=> [[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]]
  #  a.permutation(0).to_a #=> [[]] # one permutation of length 0
  #  a.permutation(4).to_a #=> []   # no permutations of length 4
  def permutation(n=self.size, &block)
    size = self.size
    return to_enum(:permutation, n) unless block
    return if n > size
    if n == 0
       yield []
    else
      i = 0
      while i<size
        result = [self[i]]
        if n-1 > 0
          ary = self[0...i] + self[i+1..-1]
          ary.permutation(n-1) do |c|
            yield result + c
          end
        else
          yield result
        end
        i += 1
      end
    end
  end

  ##
  # call-seq:
  #    ary.combination(n) { |c| block }    -> ary
  #    ary.combination(n)                  -> Enumerator
  #
  # When invoked with a block, yields all combinations of length +n+ of elements
  # from the array and then returns the array itself.
  #
  # The implementation makes no guarantees about the order in which the
  # combinations are yielded.
  #
  # If no block is given, an Enumerator is returned instead.
  #
  # Examples:
  #
  #    a = [1, 2, 3, 4]
  #    a.combination(1).to_a  #=> [[1],[2],[3],[4]]
  #    a.combination(2).to_a  #=> [[1,2],[1,3],[1,4],[2,3],[2,4],[3,4]]
  #    a.combination(3).to_a  #=> [[1,2,3],[1,2,4],[1,3,4],[2,3,4]]
  #    a.combination(4).to_a  #=> [[1,2,3,4]]
  #    a.combination(0).to_a  #=> [[]] # one combination of length 0
  #    a.combination(5).to_a  #=> []   # no combinations of length 5

  def combination(n, &block)
    size = self.size
    return to_enum(:combination, n) unless block
    return if n > size
    if n == 0
       yield []
    elsif n == 1
      i = 0
      while i<size
        yield [self[i]]
        i += 1
      end
    else
      i = 0
      while i<size
        result = [self[i]]
        self[i+1..-1].combination(n-1) do |c|
          yield result + c
        end
        i += 1
      end
    end
  end

  ##
  # call-seq:
  #    ary.transpose -> new_ary
  #
  # Assumes that self is an array of arrays and transposes the rows and columns.
  #
  # If the length of the subarrays don’t match, an IndexError is raised.
  #
  # Examples:
  #
  #    a = [[1,2], [3,4], [5,6]]
  #    a.transpose   #=> [[1, 3, 5], [2, 4, 6]]

  def transpose
    return [] if empty?

    column_count = nil
    self.each do |row|
      raise TypeError unless row.is_a?(Array)
      column_count ||= row.count
      raise IndexError, 'element size differs' unless column_count == row.count
    end

    Array.new(column_count) do |column_index|
      self.map { |row| row[column_index] }
    end
  end
end
