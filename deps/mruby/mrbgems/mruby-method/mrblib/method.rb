class Method
  def to_proc
    m = self
    lambda { |*args, &b|
      m.call(*args, &b)
    }
  end

  def owner
    @owner
  end

  def receiver
    @recv
  end

  def name
    @name
  end
end
