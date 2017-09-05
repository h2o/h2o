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
  def each(&block)
    return to_enum :each unless block

    idx = 0
    while idx < length
      block.call(self[idx])
      idx += 1
    end
    self
  end

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
    raise TypeError, "expected Integer for 1st argument" unless size.kind_of? Integer
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

  def _inspect
    return "[]" if self.size == 0
    "["+self.map{|x|x.inspect}.join(", ")+"]"
  end
  ##
  # Return the contents of this array as a string.
  #
  # ISO 15.2.12.5.31 (x)
  def inspect
    begin
      self._inspect
    rescue SystemStackError
      "[...]"
    end
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

  # internal method to convert multi-value to single value
  def __svalue
    return self.first if self.size < 2
    self
  end
end

##
# Array is enumerable
class Array
  # ISO 15.2.12.3
  include Enumerable

  ##
  # Quick sort
  # a     : the array to sort
  # left  : the beginning of sort region
  # right : the end of sort region
  def __sort_sub__(a, left, right, &block)
    if left < right
      i = left
      j = right
      pivot = a[i + (j - i) / 2]
      while true
        while ((block)? block.call(a[i], pivot): (a[i] <=> pivot)) < 0
          i += 1
        end
        while ((block)? block.call(pivot, a[j]): (pivot <=> a[j])) < 0
          j -= 1
        end
        break if (i >= j)
        tmp = a[i]; a[i] = a[j]; a[j] = tmp;
        i += 1
        j -= 1
      end
      __sort_sub__(a, left, i-1, &block)
      __sort_sub__(a, j+1, right, &block)
    end
  end
  #  private :__sort_sub__

  ##
  # Sort all elements and replace +self+ with these
  # elements.
  def sort!(&block)
    size = self.size
    if size > 1
      __sort_sub__(self, 0, size - 1, &block)
    end
    self
  end

  def sort(&block)
    self.dup.sort!(&block)
  end
end
