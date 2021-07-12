class String

  ##
  # call-seq:
  #    string.clear    ->  string
  #
  # Makes string empty.
  #
  #    a = "abcde"
  #    a.clear    #=> ""
  #
  def clear
    self.replace("")
  end

  ##
  # call-seq:
  #    str.lstrip   -> new_str
  #
  # Returns a copy of <i>str</i> with leading whitespace removed. See also
  # <code>String#rstrip</code> and <code>String#strip</code>.
  #
  #    "  hello  ".lstrip   #=> "hello  "
  #    "hello".lstrip       #=> "hello"
  #
  def lstrip
    a = 0
    z = self.size - 1
    a += 1 while a <= z and " \f\n\r\t\v".include?(self[a])
    (z >= 0) ? self[a..z] : ""
  end

  ##
  # call-seq:
  #    str.rstrip   -> new_str
  #
  # Returns a copy of <i>str</i> with trailing whitespace removed. See also
  # <code>String#lstrip</code> and <code>String#strip</code>.
  #
  #    "  hello  ".rstrip   #=> "  hello"
  #    "hello".rstrip       #=> "hello"
  #
  def rstrip
    a = 0
    z = self.size - 1
    z -= 1 while a <= z and " \f\n\r\t\v\0".include?(self[z])
    (z >= 0) ? self[a..z] : ""
  end

  ##
  # call-seq:
  #    str.strip   -> new_str
  #
  # Returns a copy of <i>str</i> with leading and trailing whitespace removed.
  #
  #    "    hello    ".strip   #=> "hello"
  #    "\tgoodbye\r\n".strip   #=> "goodbye"
  #
  def strip
    a = 0
    z = self.size - 1
    a += 1 while a <= z and " \f\n\r\t\v".include?(self[a])
    z -= 1 while a <= z and " \f\n\r\t\v\0".include?(self[z])
    (z >= 0) ? self[a..z] : ""
  end

  ##
  # call-seq:
  #    str.lstrip!   -> self or nil
  #
  # Removes leading whitespace from <i>str</i>, returning <code>nil</code> if no
  # change was made. See also <code>String#rstrip!</code> and
  # <code>String#strip!</code>.
  #
  #    "  hello  ".lstrip   #=> "hello  "
  #    "hello".lstrip!      #=> nil
  #
  def lstrip!
    raise FrozenError, "can't modify frozen String" if frozen?
    s = self.lstrip
    (s == self) ? nil : self.replace(s)
  end

  ##
  # call-seq:
  #    str.rstrip!   -> self or nil
  #
  # Removes trailing whitespace from <i>str</i>, returning <code>nil</code> if
  # no change was made. See also <code>String#lstrip!</code> and
  # <code>String#strip!</code>.
  #
  #    "  hello  ".rstrip   #=> "  hello"
  #    "hello".rstrip!      #=> nil
  #
  def rstrip!
    raise FrozenError, "can't modify frozen String" if frozen?
    s = self.rstrip
    (s == self) ? nil : self.replace(s)
  end

  ##
  #  call-seq:
  #     str.strip!   -> str or nil
  #
  #  Removes leading and trailing whitespace from <i>str</i>. Returns
  #  <code>nil</code> if <i>str</i> was not altered.
  #
  def strip!
    raise FrozenError, "can't modify frozen String" if frozen?
    s = self.strip
    (s == self) ? nil : self.replace(s)
  end

  ##
  # call-seq:
  #    str.casecmp(other_str)   -> -1, 0, +1 or nil
  #
  # Case-insensitive version of <code>String#<=></code>.
  #
  #    "abcdef".casecmp("abcde")     #=> 1
  #    "aBcDeF".casecmp("abcdef")    #=> 0
  #    "abcdef".casecmp("abcdefg")   #=> -1
  #    "abcdef".casecmp("ABCDEF")    #=> 0
  #
  def casecmp(str)
    self.downcase <=> str.__to_str.downcase
  rescue NoMethodError
    nil
  end

  ##
  # call-seq:
  #   str.casecmp?(other)  -> true, false, or nil
  #
  # Returns true if str and other_str are equal after case folding,
  # false if they are not equal, and nil if other_str is not a string.

  def casecmp?(str)
    c = self.casecmp(str)
    return nil if c.nil?
    return c == 0
  end

  def partition(sep)
    raise TypeError, "type mismatch: #{sep.class} given" unless sep.is_a? String
    n = index(sep)
    unless n.nil?
      m = n + sep.size
      [ slice(0, n), sep, slice(m, size - m) ]
    else
      [ self, "", "" ]
    end
  end

  def rpartition(sep)
    raise TypeError, "type mismatch: #{sep.class} given" unless sep.is_a? String
    n = rindex(sep)
    unless n.nil?
      m = n + sep.size
      [ slice(0, n), sep, slice(m, size - m) ]
    else
      [ "", "", self ]
    end
  end

  ##
  # call-seq:
  #    str.slice!(fixnum)           -> new_str or nil
  #    str.slice!(fixnum, fixnum)   -> new_str or nil
  #    str.slice!(range)            -> new_str or nil
  #    str.slice!(other_str)        -> new_str or nil
  #
  # Deletes the specified portion from <i>str</i>, and returns the portion
  # deleted.
  #
  #    string = "this is a string"
  #    string.slice!(2)        #=> "i"
  #    string.slice!(3..6)     #=> " is "
  #    string.slice!("r")      #=> "r"
  #    string                  #=> "thsa sting"
  #
  def slice!(arg1, arg2=nil)
    raise FrozenError, "can't modify frozen String" if frozen?
    raise "wrong number of arguments (for 1..2)" if arg1.nil? && arg2.nil?

    if !arg1.nil? && !arg2.nil?
      idx = arg1
      idx += self.size if arg1 < 0
      if idx >= 0 && idx <= self.size && arg2 > 0
        str = self[idx, arg2]
      else
        return nil
      end
    else
      validated = false
      if arg1.kind_of?(Range)
        beg = arg1.begin
        ed = arg1.end
        beg += self.size if beg < 0
        ed += self.size if ed < 0
        ed -= 1 if arg1.exclude_end?
        validated = true
      elsif arg1.kind_of?(String)
        validated = true
      else
        idx = arg1
        idx += self.size if arg1 < 0
        validated = true if idx >=0 && arg1 < self.size
      end
      if validated
        str = self[arg1]
      else
        return nil
      end
    end
    unless str.nil? || str == ""
      if !arg1.nil? && !arg2.nil?
        idx = arg1 >= 0 ? arg1 : self.size+arg1
        str2 = self[0...idx] + self[idx+arg2..-1].to_s
      else
        if arg1.kind_of?(Range)
          idx = beg >= 0 ? beg : self.size+beg
          idx2 = ed>= 0 ? ed : self.size+ed
          str2 = self[0...idx] + self[idx2+1..-1].to_s
        elsif arg1.kind_of?(String)
          idx = self.index(arg1)
          str2 = self[0...idx] + self[idx+arg1.size..-1] unless idx.nil?
        else
          idx = arg1 >= 0 ? arg1 : self.size+arg1
          str2 = self[0...idx] + self[idx+1..-1].to_s
        end
      end
      self.replace(str2) unless str2.nil?
    end
    str
  end

  ##
  #  call-seq:
  #     str.insert(index, other_str)   -> str
  #
  #  Inserts <i>other_str</i> before the character at the given
  #  <i>index</i>, modifying <i>str</i>. Negative indices count from the
  #  end of the string, and insert <em>after</em> the given character.
  #  The intent is insert <i>aString</i> so that it starts at the given
  #  <i>index</i>.
  #
  #     "abcd".insert(0, 'X')    #=> "Xabcd"
  #     "abcd".insert(3, 'X')    #=> "abcXd"
  #     "abcd".insert(4, 'X')    #=> "abcdX"
  #     "abcd".insert(-3, 'X')   #=> "abXcd"
  #     "abcd".insert(-1, 'X')   #=> "abcdX"
  #
  def insert(idx, str)
    if idx == -1
      return self << str
    elsif idx < 0
      idx += 1
    end
    self[idx, 0] = str
    self
  end

  ##
  #  call-seq:
  #     str.ljust(integer, padstr=' ')   -> new_str
  #
  #  If <i>integer</i> is greater than the length of <i>str</i>, returns a new
  #  <code>String</code> of length <i>integer</i> with <i>str</i> left justified
  #  and padded with <i>padstr</i>; otherwise, returns <i>str</i>.
  #
  #     "hello".ljust(4)            #=> "hello"
  #     "hello".ljust(20)           #=> "hello               "
  #     "hello".ljust(20, '1234')   #=> "hello123412341234123"
  def ljust(idx, padstr = ' ')
    raise ArgumentError, 'zero width padding' if padstr == ''
    return self if idx <= self.size
    pad_repetitions = (idx / padstr.length).ceil
    padding = (padstr * pad_repetitions)[0...(idx - self.length)]
    self + padding
  end

  ##
  #  call-seq:
  #     str.rjust(integer, padstr=' ')   -> new_str
  #
  #  If <i>integer</i> is greater than the length of <i>str</i>, returns a new
  #  <code>String</code> of length <i>integer</i> with <i>str</i> right justified
  #  and padded with <i>padstr</i>; otherwise, returns <i>str</i>.
  #
  #     "hello".rjust(4)            #=> "hello"
  #     "hello".rjust(20)           #=> "               hello"
  #     "hello".rjust(20, '1234')   #=> "123412341234123hello"
  def rjust(idx, padstr = ' ')
    raise ArgumentError, 'zero width padding' if padstr == ''
    return self if idx <= self.size
    pad_repetitions = (idx / padstr.length).ceil
    padding = (padstr * pad_repetitions)[0...(idx - self.length)]
    padding + self
  end

  def chars(&block)
    if block_given?
      self.split('').each do |i|
        block.call(i)
      end
      self
    else
      self.split('')
    end
  end

  ##
  # Call the given block for each character of
  # +self+.
  def each_char(&block)
    return to_enum :each_char unless block
    pos = 0
    while pos < self.size
      block.call(self[pos])
      pos += 1
    end
    self
  end

  def codepoints(&block)
    len = self.size

    if block_given?
      self.split('').each do|x|
        block.call(x.ord)
      end
      self
    else
      self.split('').map{|x| x.ord}
    end
  end
  alias each_codepoint codepoints

  ##
  # call-seq:
  #    str.prepend(other_str)  -> str
  #
  # Prepend---Prepend the given string to <i>str</i>.
  #
  #    a = "world"
  #    a.prepend("hello ") #=> "hello world"
  #    a                   #=> "hello world"
  def prepend(arg)
    self[0, 0] = arg
    self
  end

  ##
  #  call-seq:
  #    string.lines                ->  array of string
  #    string.lines {|s| block}    ->  array of string
  #
  #  Returns strings per line;
  #
  #    a = "abc\ndef"
  #    a.lines    #=> ["abc\n", "def"]
  #
  #  If a block is given, it works the same as <code>each_line</code>.
  def lines(&blk)
    lines = self.__lines
    if blk
      lines.each do |line|
        blk.call(line)
      end
    end
    lines
  end

  ##
  #  call-seq:
  #     str.upto(other_str, exclusive=false) {|s| block }   -> str
  #     str.upto(other_str, exclusive=false)                -> an_enumerator
  #
  #  Iterates through successive values, starting at <i>str</i> and
  #  ending at <i>other_str</i> inclusive, passing each value in turn to
  #  the block. The <code>String#succ</code> method is used to generate
  #  each value.  If optional second argument exclusive is omitted or is false,
  #  the last value will be included; otherwise it will be excluded.
  #
  #  If no block is given, an enumerator is returned instead.
  #
  #     "a8".upto("b6") {|s| print s, ' ' }
  #     for s in "a8".."b6"
  #       print s, ' '
  #     end
  #
  #  <em>produces:</em>
  #
  #     a8 a9 b0 b1 b2 b3 b4 b5 b6
  #     a8 a9 b0 b1 b2 b3 b4 b5 b6
  #
  #  If <i>str</i> and <i>other_str</i> contains only ascii numeric characters,
  #  both are recognized as decimal numbers. In addition, the width of
  #  string (e.g. leading zeros) is handled appropriately.
  #
  #     "9".upto("11").to_a   #=> ["9", "10", "11"]
  #     "25".upto("5").to_a   #=> []
  #     "07".upto("11").to_a  #=> ["07", "08", "09", "10", "11"]
  def upto(max, exclusive=false, &block)
    return to_enum(:upto, max, exclusive) unless block
    raise TypeError, "no implicit conversion of #{max.class} into String" unless max.kind_of? String

    len = self.length
    maxlen = max.length
    # single character
    if len == 1 and maxlen == 1
      c = self.ord
      e = max.ord
      while c <= e
        break if exclusive and c == e
        yield c.chr(__ENCODING__)
        c += 1
      end
      return self
    end
    # both edges are all digits
    bi = self.to_i(10)
    ei = max.to_i(10)
    len = self.length
    if (bi > 0 or bi == "0"*len) and (ei > 0 or ei == "0"*maxlen)
      while bi <= ei
        break if exclusive and bi == ei
        s = bi.to_s
        s = s.rjust(len, "0") if s.length < len
        yield s
        bi += 1
      end
      return self
    end
    bs = self
    while true
      n = (bs <=> max)
      break if n > 0
      break if exclusive and n == 0
      yield bs
      break if n == 0
      bs = bs.succ
    end
    self
  end
end
