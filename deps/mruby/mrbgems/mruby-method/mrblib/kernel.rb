module Kernel
  def singleton_method(name)
    m = method(name)
    if m.owner != singleton_class
      raise NameError, "undefined method `#{name}' for class `#{singleton_class}'"
    end
    m
  end
end
