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
  def each_line(&block)
    offset = 0
    while pos = self.index("\n", offset)
      block.call(self[offset, pos + 1 - offset])
      offset = pos + 1
    end
    block.call(self[offset, self.size - offset]) if self.size > offset
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
    if args.size == 2
      s = ""
      i = 0
      while j = index(args[0], i)
        seplen = args[0].length
        k = j + seplen
        pre = self[0, j]
        post = self[k, length-k]
        s += self[i, j-i] + args[1].__sub_replace(pre, args[0], post)
        i = k
      end
      s + self[i, length-i]
    elsif args.size == 1 && block
      split(args[0], -1).join(block.call(args[0]))
    else
      raise ArgumentError, "wrong number of arguments"
    end
  end

  ##
  # Replace all matches of +pattern+ with +replacement+.
  # Call block (if given) for each match and replace
  # +pattern+ with the value of the block. Modify
  # +self+ with the final value.
  #
  # ISO 15.2.10.5.19
  def gsub!(*args, &block)
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
    if args.size == 2
      pre, post = split(args[0], 2)
      return self unless post # The sub target wasn't found in the string
      pre + args[1].__sub_replace(pre, args[0], post) + post
    elsif args.size == 1 && block
      split(args[0], 2).join(block.call(args[0]))
    else
      raise ArgumentError, "wrong number of arguments"
    end
  end

  ##
  # Replace only the first match of +pattern+ with
  # +replacement+. Call block (if given) for each
  # match and replace +pattern+ with the value of the
  # block. Modify +self+ with the final value.
  #
  # ISO 15.2.10.5.37
  def sub!(*args, &block)
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
