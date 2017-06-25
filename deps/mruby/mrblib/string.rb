##
# String
#
# ISO 15.2.10
class String
  include Comparable
  ##
  # Calls the given block for each line
  # and pass the respective line.
  #
  # ISO 15.2.10.5.15
  def each_line(rs = "\n", &block)
    return to_enum(:each_line, rs, &block) unless block
    return block.call(self) if rs.nil?
    rs = rs.to_str
    offset = 0
    rs_len = rs.length
    this = dup
    while pos = this.index(rs, offset)
      block.call(this[offset, pos + rs_len - offset])
      offset = pos + rs_len
    end
    block.call(this[offset, this.size - offset]) if this.size > offset
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
      replace = replace.to_str
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
    raise RuntimeError, "can't modify frozen String" if frozen?
    return to_enum(:gsub!, *args) if args.length == 1 && !block
    str = self.gsub(*args, &block)
    return nil if str == self
    self.replace(str)
  end

  ##
  # Calls the given block for each match of +pattern+
  # If no block is given return an array with all
  # matches of +pattern+.
  #
  # ISO 15.2.10.5.32
  def scan(reg, &block)
    ### *** TODO *** ###
    unless Object.const_defined?(:Regexp)
      raise NotImplementedError, "scan not available (yet)"
    end
  end

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
    pattern = pattern.to_str
    if args.length == 2 && block
      block = nil
    end
    unless block
      replace = replace.to_str
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
    raise RuntimeError, "can't modify frozen String" if frozen?
    str = self.sub(*args, &block)
    return nil if str == self
    self.replace(str)
  end

  ##
  # Call the given block for each character of
  # +self+.
  def each_char(&block)
    pos = 0
    while pos < self.size
      block.call(self[pos])
      pos += 1
    end
    self
  end

  ##
  # Call the given block for each byte of +self+.
  def each_byte(&block)
    bytes = self.bytes
    pos = 0
    while pos < bytes.size
      block.call(bytes[pos])
      pos += 1
    end
    self
  end

  ##
  # Modify +self+ by replacing the content of +self+.
  # The portion of the string affected is determined using the same criteria as +String#[]+.
  def []=(*args)
    anum = args.size
    if anum == 2
      pos, value = args
      case pos
      when String
        posnum = self.index(pos)
        if posnum
          b = self[0, posnum.to_i]
          a = self[(posnum + pos.length)..-1]
          self.replace([b, value, a].join(''))
        else
          raise IndexError, "string not matched"
        end
      when Range
        head = pos.begin
        tail = pos.end
        tail += self.length if tail < 0
        unless pos.exclude_end?
          tail += 1
        end
        return self[head, tail-head]=value
      else
        pos += self.length if pos < 0
        if pos < 0 || pos > self.length
          raise IndexError, "index #{args[0]} out of string"
        end
        b = self[0, pos.to_i]
        a = self[pos + 1..-1]
        self.replace([b, value, a].join(''))
      end
      return value
    elsif anum == 3
      pos, len, value = args
      pos += self.length if pos < 0
      if pos < 0 || pos > self.length
        raise IndexError, "index #{args[0]} out of string"
      end
      if len < 0
        raise IndexError, "negative length #{len}"
      end
      b = self[0, pos.to_i]
      a = self[pos + len..-1]
      self.replace([b, value, a].join(''))
      return value
    else
      raise ArgumentError, "wrong number of arguments (#{anum} for 2..3)"
    end
  end

  ##
  # ISO 15.2.10.5.3
  def =~(re)
    raise TypeError, "type mismatch: String given" if re.respond_to? :to_str
    re =~ self
  end

  ##
  # ISO 15.2.10.5.27
  def match(re, &block)
    if re.respond_to? :to_str
      if Object.const_defined?(:Regexp)
        r = Regexp.new(re)
        r.match(self, &block)
      else
        raise NotImplementedError, "String#match needs Regexp class"
      end
    else
      re.match(self, &block)
    end
  end
end

##
# String is comparable
#
# ISO 15.2.10.3
module Comparable; end
class String
  include Comparable
end
