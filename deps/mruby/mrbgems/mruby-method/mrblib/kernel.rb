module Kernel
  def singleton_method(name)
    m = method(name)
    sc = (class <<self; self; end)
    if m.owner != sc
      raise NameError, "undefined method '#{name}' for class '#{sc}'"
    end
    m
  end
end
