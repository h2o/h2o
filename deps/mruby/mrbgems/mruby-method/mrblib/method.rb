class Method
  def to_proc
    m = self
    lambda { |*args, **opts, &b|
      m.call(*args, **opts, &b)
    }
  end

  def <<(other)
    ->(*args, **opts, &block) { call(other.call(*args, **opts, &block)) }
  end

  def >>(other)
    ->(*args, **opts, &block) { other.call(call(*args, **opts, &block)) }
  end
end
