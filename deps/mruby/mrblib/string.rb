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
    self_len = length
    sep_len = separator.length
    should_yield_subclass_instances = self.class != String

    while (pointer = string.index(separator, start))
      pointer += sep_len
      pointer += 1 while paragraph_mode && string[pointer] == "\n"
      if should_yield_subclass_instances
        block.call(self.class.new(string[start, pointer - start]))
      else
        block.call(string[start, pointer - start])
      end
      start = pointer
    end
    return self if start == self_len

    if should_yield_subclass_instances
      block.call(self.class.new(string[start, self_len - start]))
    else
      block.call(string[start, self_len - start])
    end
    self
  end

  # private method for gsub/sub
  def __sub_replace(pre, m, post)
    s = ""
    i = 0
    while j = index("\\", i)
      break if j == length-1
      t = case self[j+1]
          when "\\"
            "\\"
          when "`"
            pre
          when "&", "0"
            m
          when "'"
            post
          when "1", "2", "3", "4", "5", "6", "7", "8", "9"
            ""
          else
            self[j, 2]
          end
      s += self[i, j-i] + t
      i = j + 2
    end
    s + self[i, length-i]
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
    raise ArgumentError, "wrong number of arguments" unless (1..2).include?(args.length)

    pattern, replace = *args
    plen = pattern.length
    if args.length == 2 && block
      block = nil
    end
    if !replace.nil? || !block
      replace.__to_str
    end
    offset = 0
    result = []
    while found = index(pattern, offset)
      result << self[offset, found - offset]
      offset = found + plen
      result << if block
        block.call(pattern).to_s
      else
        replace.__sub_replace(self[0, found], pattern, self[offset..-1] || "")
      end
      if plen == 0
        result << self[offset, 1]
        offset += 1
      end
    end
    result << self[offset..-1] if offset < length
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
    pattern.__to_str
    if args.length == 2 && block
      block = nil
    end
    unless block
      replace.__to_str
    end
    result = []
    this = dup
    found = index(pattern)
    return this unless found
    result << this[0, found]
    offset = found + pattern.length
    result << if block
      block.call(pattern).to_s
    else
      replace.__sub_replace(this[0, found], pattern, this[offset..-1] || "")
    end
    result << this[offset..-1] if offset < length
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
    bytes = self.bytes
    pos = 0
    while pos < bytes.size
      block.call(bytes[pos])
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
