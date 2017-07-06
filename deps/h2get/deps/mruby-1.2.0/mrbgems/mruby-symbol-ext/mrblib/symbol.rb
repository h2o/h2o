class Symbol
  include Comparable

  alias intern to_sym

  def to_proc
    ->(obj,*args,&block) do
      obj.__send__(self, *args, &block)
    end
  end

  ##
  # call-seq:
  #   sym.capitalize  -> symbol
  #
  # Same as <code>sym.to_s.capitalize.intern</code>.

  def capitalize
    (self.to_s.capitalize! || self).to_sym
  end

  ##
  # call-seq:
  #   sym.downcase  -> symbol
  #
  # Same as <code>sym.to_s.downcase.intern</code>.

  def downcase
    (self.to_s.downcase! || self).to_sym
  end

  ##
  # call-seq:
  #   sym.upcase    -> symbol
  #
  # Same as <code>sym.to_s.upcase.intern</code>.

  def upcase
    (self.to_s.upcase! || self).to_sym
  end

  ##
  # call-seq:
  #   sym.casecmp(other)  -> -1, 0, +1 or nil
  #
  # Case-insensitive version of <code>Symbol#<=></code>.

  def casecmp(other)
    return nil unless other.kind_of?(Symbol)
    lhs =  self.to_s; lhs.upcase!
    rhs = other.to_s; rhs.upcase!
    lhs <=> rhs
  end

  #
  # call-seq:
  #   sym.empty?   -> true or false
  #
  # Returns that _sym_ is :"" or not.

  def empty?
    self.length == 0
  end

end
