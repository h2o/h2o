##
# String
#
# ISO 15.2.10
class String
  # ISO 15.2.10.3
  include Comparable

  ##
  # Calls the given block for each line
  # and pass the respective line.
  #
  # ISO 15.2.10.5.15
  def each_line(separator = "\n", &block)
    return to_enum(:each_line, separator) unless block

    if separator.nil?
      block.call(self)
      return self
    end
    raise TypeError unless separator.is_a?(String)

    paragraph_mode = false
    if separator.empty?
      paragraph_mode = true
      separator = "\n\n"
    end
    start = 0
    string = dup
    self_len = self.bytesize
    sep_len = separator.bytesize

    while (pointer = string.byteindex(separator, start))
      pointer += sep_len
      pointer += 1 while paragraph_mode && string.getbyte(pointer) == 10 # 10 == \n
      block.call(string.byteslice(start, pointer - start))
      start = pointer
    end
    return self if start == self_len

    block.call(string.byteslice(start, self_len - start))
    self
  end

  ##
  # Replace all matches of +pattern+ with +replacement+.
  # Call block (if given) for each match and replace
  # +pattern+ with the value of the block. Return the
  # final value.
  #
  # ISO 15.2.10.5.18
  def gsub(*args, &block)
    return to_enum(:gsub, *args) if args.length == 1 && !block
    raise ArgumentError, "wrong number of arguments (given #{args.length}, expected 1..2)" unless (1..2).include?(args.length)

    pattern, replace = *args
    plen = pattern.length
    if args.length == 2 && block
      block = nil
    end
    offset = 0
    result = []
    while found = self.byteindex(pattern, offset)
      result << self.byteslice(offset, found - offset)
      offset = found + plen
      result << if block
        block.call(pattern).to_s
      else
        self.__sub_replace(replace, pattern, found)
      end
      if plen == 0
        result << self.byteslice(offset, 1)
        offset += 1
      end
    end
    result << self.byteslice(offset..-1) if offset < length
    result.join
  end

  ##
  # Replace all matches of +pattern+ with +replacement+.
  # Call block (if given) for each match and replace
  # +pattern+ with the value of the block. Modify
  # +self+ with the final value.
  #
  # ISO 15.2.10.5.19
  def gsub!(*args, &block)
    raise FrozenError, "can't modify frozen String" if frozen?
    return to_enum(:gsub!, *args) if args.length == 1 && !block
    str = self.gsub(*args, &block)
    return nil unless self.index(args[0])
    self.replace(str)
  end

#  ##
#  # Calls the given block for each match of +pattern+
#  # If no block is given return an array with all
#  # matches of +pattern+.
#  #
#  # ISO 15.2.10.5.32
#  def scan(pattern, &block)
#    # TODO: String#scan is not implemented yet
#  end

  ##
  # Replace only the first match of +pattern+ with
  # +replacement+. Call block (if given) for each
  # match and replace +pattern+ with the value of the
  # block. Return the final value.
  #
  # ISO 15.2.10.5.36
  def sub(*args, &block)
    unless (1..2).include?(args.length)
      raise ArgumentError, "wrong number of arguments (given #{args.length}, expected 2)"
    end

    pattern, replace = *args
    if args.length == 2 && block
      block = nil
    end
    result = []
    found = self.index(pattern)
    return self.dup unless found
    result << self.byteslice(0, found)
    offset = found + pattern.length
    result << if block
      block.call(pattern).to_s
    else
      self.__sub_replace(replace, pattern, found)
    end
    result << self.byteslice(offset..-1) if offset < length
    result.join
  end

  ##
  # Replace only the first match of +pattern+ with
  # +replacement+. Call block (if given) for each
  # match and replace +pattern+ with the value of the
  # block. Modify +self+ with the final value.
  #
  # ISO 15.2.10.5.37
  def sub!(*args, &block)
    raise FrozenError, "can't modify frozen String" if frozen?
    str = self.sub(*args, &block)
    return nil unless self.index(args[0])
    self.replace(str)
  end

  ##
  # Call the given block for each byte of +self+.
  def each_byte(&block)
    return to_enum(:each_byte, &block) unless block
    pos = 0
    while pos < bytesize
      block.call(getbyte(pos))
      pos += 1
    end
    self
  end

  # those two methods requires Regexp that is optional in mruby
  ##
  # ISO 15.2.10.5.3
  #def =~(re)
  # re =~ self
  #end

  ##
  # ISO 15.2.10.5.27
  #def match(re, &block)
  #  re.match(self, &block)
  #end
end
