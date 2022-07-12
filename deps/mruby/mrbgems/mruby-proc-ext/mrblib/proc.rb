class Proc

  def ===(*args)
    call(*args)
  end

  def yield(*args)
    call(*args)
  end

  def to_proc
    self
  end

  def curry(arity=self.arity)
    type = :proc
    abs = lambda {|a| a < 0 ? -a - 1 : a}
    arity = abs[arity]
    if lambda?
      type = :lambda
      self_arity = self.arity
      if (self_arity >= 0 && arity != self_arity) ||
         (self_arity < 0 && abs[self_arity] > arity)
        raise ArgumentError, "wrong number of arguments (given #{arity}, expected #{abs[self_arity]})"
      end
    end

    pproc = self
    make_curry = proc do |given_args=[]|
      __send__(type) do |*args|
        new_args = given_args + args
        if new_args.size >= arity
          pproc[*new_args]
        else
          make_curry[new_args]
        end
      end
    end
    make_curry.call
  end

  def <<(other)
    ->(*args, **opts, &block) { call(other.call(*args, **opts, &block)) }
  end

  def >>(other)
    ->(*args, **opts, &block) { other.call(call(*args, **opts, &block)) }
  end

end
