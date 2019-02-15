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

  def <<(other)
    ->(*args, &block) { call(other.call(*args, &block)) }
  end

  def >>(other)
    ->(*args, &block) { other.call(call(*args, &block)) }
  end
end
