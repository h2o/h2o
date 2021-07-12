##
# ensure Test

class EnsureYieldBreak
  attr_reader :ensure_context
  def try
    yield
  ensure
    @ensure_context = self
  end
end

assert('ensure - context - yield') do
  yielder = EnsureYieldBreak.new
  yielder.try do
  end
  assert_equal yielder, yielder.ensure_context
end

assert('ensure - context - yield and break') do
  yielder = EnsureYieldBreak.new
  yielder.try do
    break
  end
  assert_equal yielder, yielder.ensure_context
end

assert('ensure - context - yield and return') do
  yielder = EnsureYieldBreak.new
  lambda do
    yielder.try do
      return
    end
  end.call
  assert_equal yielder, yielder.ensure_context
end
