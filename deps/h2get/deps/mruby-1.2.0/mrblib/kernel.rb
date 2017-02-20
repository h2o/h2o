##
# Kernel
#
# ISO 15.3.1
module Kernel

  # 15.3.1.2.1 Kernel.`
  # provided by Kernel#`
  # 15.3.1.3.5
  def `(s)
    raise NotImplementedError.new("backquotes not implemented")
  end

  ##
  # 15.3.1.2.3  Kernel.eval
  # 15.3.1.3.12 Kernel#eval
  # NotImplemented by mruby core; use mruby-eval gem

  ##
  # ISO 15.3.1.2.8 Kernel.loop
  # provided by Kernel#loop

  ##
  # Calls the given block repetitively.
  #
  # ISO 15.3.1.3.29
  def loop(&block)
    return to_enum :loop unless block

    while true
      yield
    end
  rescue StopIteration => e
    e.result
  end

  # 11.4.4 Step c)
  def !~(y)
    !(self =~ y)
  end

  # internal method for inspect
  def _inspect
    self.inspect
  end

  def to_enum(*a)
    raise NotImplementedError.new("fiber required for enumerator")
  end
end
