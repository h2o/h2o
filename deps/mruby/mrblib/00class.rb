class BasicObject
  def !=(other)
    if self == other
      false
    else
      true
    end
  end
end

class Module
   # 15.2.2.4.12
  def attr_accessor(*names)
    attr_reader(*names)
    attr_writer(*names)
  end
  # 15.2.2.4.11
  alias attr attr_reader
  #def attr(name)
  #  attr_reader(name)
  #end

  # 15.2.2.4.27
  def include(*args)
    args.reverse.each do |m|
      m.append_features(self)
      m.included(self)
    end
    self
  end

  def prepend(*args)
    args.reverse.each do |m|
      m.prepend_features(self)
      m.prepended(self)
    end
    self
  end
end
