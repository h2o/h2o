##
# ensure Test

assert('ensure - context - yield') do
  class EnsureYieldBreak
    attr_reader :ensure_context
    def try
      yield
    ensure
      @ensure_context = self
    end
  end

  yielder = EnsureYieldBreak.new
  yielder.try do
  end
  assert_equal yielder, yielder.ensure_context
end

assert('ensure - context - yield and break') do
  class EnsureYieldBreak
    attr_reader :ensure_context
    def try
      yield
    ensure
      @ensure_context = self
    end
  end

  yielder = EnsureYieldBreak.new
  yielder.try do
    break
  end
  assert_equal yielder, yielder.ensure_context
end

assert('ensure - context - yield and return') do
  class EnsureYieldBreak
    attr_reader :ensure_context
    def try
      yield
    ensure
      @ensure_context = self
    end
  end

  yielder = EnsureYieldBreak.new
  lambda do
    yielder.try do
      return
    end
  end.call
  assert_equal yielder, yielder.ensure_context
end
