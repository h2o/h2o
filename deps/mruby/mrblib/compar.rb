##
# Comparable
#
# ISO 15.3.3
module Comparable

  ##
  # call-seq:
  #   obj < other    -> true or false
  #
  # Return true if +self+ is less
  # than +other+. Otherwise return
  # false.
  #
  # ISO 15.3.3.2.1
  def < other
    cmp = self <=> other
    if cmp.nil?
      raise ArgumentError, "comparison of #{self.class} with #{other.class} failed"
    end
    cmp < 0
  end

  ##
  # call-seq:
  #   obj <= other   -> true or false
  #
  # Return true if +self+ is less
  # than or equal to +other+.
  # Otherwise return false.
  #
  # ISO 15.3.3.2.2
  def <= other
    cmp = self <=> other
    if cmp.nil?
      raise ArgumentError, "comparison of #{self.class} with #{other.class} failed"
    end
    cmp <= 0
  end

  ##
  # call-seq:
  #   obj == other   -> true or false
  #
  # Return true if +self+ is equal
  # to +other+. Otherwise return
  # false.
  #
  # ISO 15.3.3.2.3
  def == other
    cmp = self <=> other
    cmp == 0
  end

  ##
  # call-seq:
  #   obj > other    -> true or false
  #
  # Return true if +self+ is greater
  # than +other+. Otherwise return
  # false.
  #
  # ISO 15.3.3.2.4
  def > other
    cmp = self <=> other
    if cmp.nil?
      raise ArgumentError, "comparison of #{self.class} with #{other.class} failed"
    end
    cmp > 0
  end

  ##
  # call-seq:
  #   obj >= other   -> true or false
  #
  # Return true if +self+ is greater
  # than or equal to +other+.
  # Otherwise return false.
  #
  # ISO 15.3.3.2.5
  def >= other
    cmp = self <=> other
    if cmp.nil?
      raise ArgumentError, "comparison of #{self.class} with #{other.class} failed"
    end
    cmp >= 0
  end

  ##
  # call-seq:
  #   obj.between?(min,max) -> true or false
  #
  # Return true if +self+ is greater
  # than or equal to +min+ and
  # less than or equal to +max+.
  # Otherwise return false.
  #
  # ISO 15.3.3.2.6
  def between?(min, max)
    self >= min and self <= max
  end
end
