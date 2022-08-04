##
# Struct
#
# ISO 15.2.18
class Struct

  ##
  # Calls the given block for each element of +self+
  # and pass the respective element.
  #
  # ISO 15.2.18.4.4
  def each(&block)
    self.class.members.each{|field|
      block.call(self[field])
    }
    self
  end

  ##
  # Calls the given block for each element of +self+
  # and pass the name and value of the respective
  # element.
  #
  # ISO 15.2.18.4.5
  def each_pair(&block)
    self.class.members.each{|field|
      block.call(field.to_sym, self[field])
    }
    self
  end

  ##
  # Calls the given block for each element of +self+
  # and returns an array with all elements of which
  # block is not false.
  #
  # ISO 15.2.18.4.7
  def select(&block)
    ary = []
    self.class.members.each{|field|
      val = self[field]
      ary.push(val) if block.call(val)
    }
    ary
  end

  def _inspect(recur_list)
    return "#<struct #{self.class}:...>" if recur_list[self.object_id]
    recur_list[self.object_id] = true
    name = self.class.to_s
    if name[0] == "#"
      str = "#<struct "
    else
      str = "#<struct #{name} "
    end
    buf = []
    self.each_pair do |k,v|
      buf.push k.to_s + "=" + v._inspect(recur_list)
    end
    str + buf.join(", ") + ">"
  end

  ##
  # call-seq:
  #   struct.to_s      -> string
  #   struct.inspect   -> string
  #
  # Describe the contents of this struct in a string.
  #
  # 15.2.18.4.10(x)
  #
  def inspect
    self._inspect({})
  end

  ##
  # 15.2.18.4.11(x)
  #
  alias to_s inspect

  ##
  # call-seq:
  #   hsh.dig(key,...)                 -> object
  #
  # Extracts the nested value specified by the sequence of <i>key</i>
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
end
