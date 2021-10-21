class Module

  ##
  # call-seq:
  #   mod < other   ->  true, false, or nil
  #
  # Returns true if `mod` is a subclass of `other`. Returns
  # <code>nil</code> if there's no relationship between the two.
  # (Think of the relationship in terms of the class definition:
  # "class A < B" implies "A < B".)
  #
  def <(other)
    if self.equal?(other)
      false
    else
      self <= other
    end
  end

  ##
  # call-seq:
  #   mod <= other   ->  true, false, or nil
  #
  # Returns true if `mod` is a subclass of `other` or
  # is the same as `other`. Returns
  # <code>nil</code> if there's no relationship between the two.
  # (Think of the relationship in terms of the class definition:
  # "class A < B" implies "A < B".)
  def <=(other)
    raise TypeError, 'compared with non class/module' unless other.is_a?(Module)
    if self.ancestors.include?(other)
      return true
    elsif other.ancestors.include?(self)
      return false
    end
  end

  ##
  # call-seq:
  #  mod > other   ->  true, false, or nil
  #
  # Returns true if `mod` is an ancestor of `other`. Returns
  # <code>nil</code> if there's no relationship between the two.
  # (Think of the relationship in terms of the class definition:
  # "class A < B" implies "B > A".)
  #
  def >(other)
    if self.equal?(other)
      false
    else
      self >= other
    end
  end

  ##
  # call-seq:
  #   mod >= other   ->  true, false, or nil
  #
  # Returns true if `mod` is an ancestor of `other`, or the
  # two modules are the same. Returns
  # <code>nil</code> if there's no relationship between the two.
  # (Think of the relationship in terms of the class definition:
  # "class A < B" implies "B > A".)
  #
  def >=(other)
    raise TypeError, 'compared with non class/module' unless other.is_a?(Module)
    return other < self
  end

  ##
  # call-seq:
  #    module <=> other_module   -> -1, 0, +1, or nil
  #
  # Comparison---Returns -1, 0, +1 or nil depending on whether `module`
  # includes `other_module`, they are the same, or if `module` is included by
  # `other_module`.
  #
  # Returns `nil` if `module` has no relationship with `other_module`, if
  # `other_module` is not a module, or if the two values are incomparable.
  #
  def <=>(other)
    return 0 if self.equal?(other)
    return nil unless other.is_a?(Module)
    cmp = self < other
    return -1 if cmp
    return 1 unless cmp.nil?
    return nil
  end
end
