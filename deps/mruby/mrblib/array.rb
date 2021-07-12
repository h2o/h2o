# coding: utf-8
##
# Array
#
# ISO 15.2.12
class Array

  ##
  # Calls the given block for each element of +self+
  # and pass the respective element.
  #
  # ISO 15.2.12.5.10
  # def each(&block)
  #   return to_enum :each unless block

  #   idx = 0
  #   while idx < length
  #     block.call(self[idx])
  #     idx += 1
  #   end
  #   self
  # end

  ##
  # Calls the given block for each element of +self+
  # and pass the index of the respective element.
  #
  # ISO 15.2.12.5.11
  def each_index(&block)
    return to_enum :each_index unless block

    idx = 0
    while idx < length
      block.call(idx)
      idx += 1
    end
    self
  end

  ##
  # Calls the given block for each element of +self+
  # and pass the respective element. Each element will
  # be replaced by the resulting values.
  #
  # ISO 15.2.12.5.7
  def collect!(&block)
    return to_enum :collect! unless block

    idx = 0
    len = size
    while idx < len
      self[idx] = block.call self[idx]
      idx += 1
    end
    self
  end

  ##
  # Alias for collect!
  #
  # ISO 15.2.12.5.20
  alias map! collect!

  ##
  # Private method for Array creation.
  #
  # ISO 15.2.12.5.15
  def initialize(size=0, obj=nil, &block)
    size = size.__to_int
    raise ArgumentError, "negative array size" if size < 0

    self.clear
    if size > 0
      self[size - 1] = nil # allocate

      idx = 0
      while idx < size
        self[idx] = (block)? block.call(idx): obj
        idx += 1
      end
    end

    self
  end

  def _inspect(recur_list)
    size = self.size
    return "[]" if size == 0
    return "[...]" if recur_list[self.object_id]
    recur_list[self.object_id] = true
    ary=[]
    i=0
    while i<size
      ary<<self[i]._inspect(recur_list)
      i+=1
    end
    "["+ary.join(", ")+"]"
  end
  ##
  # Return the contents of this array as a string.
  #
  # ISO 15.2.12.5.31 (x)
  def inspect
    self._inspect({})
  end
  # ISO 15.2.12.5.32 (x)
  alias to_s inspect

  ##
  #  Equality---Two arrays are equal if they contain the same number
  #  of elements and if each element is equal to (according to
  #  Object.==) the corresponding element in the other array.
  #
  # ISO 15.2.12.5.33 (x)
  def ==(other)
    other = self.__ary_eq(other)
    return false if other == false
    return true  if other == true
    len = self.size
    i = 0
    while i < len
      return false if self[i] != other[i]
      i += 1
    end
    return true
  end

  ##
  #  Returns <code>true</code> if +self+ and _other_ are the same object,
  #  or are both arrays with the same content.
  #
  # ISO 15.2.12.5.34 (x)
  def eql?(other)
    other = self.__ary_eq(other)
    return false if other == false
    return true  if other == true
    len = self.size
    i = 0
    while i < len
      return false unless self[i].eql?(other[i])
      i += 1
    end
    return true
  end

  ##
  #  Comparison---Returns an integer (-1, 0, or +1)
  #  if this array is less than, equal to, or greater than <i>other_ary</i>.
  #  Each object in each array is compared (using <=>). If any value isn't
  #  equal, then that inequality is the return value. If all the
  #  values found are equal, then the return is based on a
  #  comparison of the array lengths.  Thus, two arrays are
  #  "equal" according to <code>Array#<=></code> if and only if they have
  #  the same length and the value of each element is equal to the
  #  value of the corresponding element in the other array.
  #
  # ISO 15.2.12.5.36 (x)
  def <=>(other)
    other = self.__ary_cmp(other)
    return 0 if 0 == other
    return nil if nil == other

    len = self.size
    n = other.size
    len = n if len > n
    i = 0
    while i < len
      n = (self[i] <=> other[i])
      return n if n.nil? || n != 0
      i += 1
    end
    len = self.size - other.size
    if len == 0
      0
    elsif len > 0
      1
    else
      -1
    end
  end

  ##
  # Delete element with index +key+
  def delete(key, &block)
    while i = self.index(key)
      self.delete_at(i)
      ret = key
    end
    return block.call if ret.nil? && block
    ret
  end
end

##
# Array is enumerable
class Array
  # ISO 15.2.12.3
  include Enumerable

  ##
  # Sort all elements and replace +self+ with these
  # elements.
  def sort!(&block)
    stack = [ [ 0, self.size - 1 ] ]
    until stack.empty?
      left, mid, right = stack.pop
      if right == nil
        right = mid
        # sort self[left..right]
        if left < right
          if left + 1 == right
            lval = self[left]
            rval = self[right]
            cmp = if block then block.call(lval,rval) else lval <=> rval end
            if cmp.nil?
              raise ArgumentError, "comparison of #{lval.inspect} and #{rval.inspect} failed"
            end
            if cmp > 0
              self[left]  = rval
              self[right] = lval
            end
          else
            mid = ((left + right + 1) / 2).floor
            stack.push [ left, mid, right ]
            stack.push [ mid, right ]
            stack.push [ left, (mid - 1) ] if left < mid - 1
          end
        end
      else
        lary = self[left, mid - left]
        lsize = lary.size

        # The entity sharing between lary and self may cause a large memory
        # copy operation in the merge loop below.  This harmless operation
        # cancels the sharing and provides a huge performance gain.
        lary[0] = lary[0]

        # merge
        lidx = 0
        ridx = mid
        (left..right).each { |i|
          if lidx >= lsize
            break
          elsif ridx > right
            self[i, lsize - lidx] = lary[lidx, lsize - lidx]
            break
          else
            lval = lary[lidx]
            rval = self[ridx]
            cmp = if block then block.call(lval,rval) else lval <=> rval end
            if cmp.nil?
              raise ArgumentError, "comparison of #{lval.inspect} and #{rval.inspect} failed"
            end
            if cmp <= 0
              self[i] = lval
              lidx += 1
            else
              self[i] = rval
              ridx += 1
            end
          end
        }
      end
    end
    self
  end

  def sort(&block)
    self.dup.sort!(&block)
  end
end
