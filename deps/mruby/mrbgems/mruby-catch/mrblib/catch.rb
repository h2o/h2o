class UncaughtThrowError < ArgumentError
  attr_reader :tag, :value
  def initialize(tag, value)
    @tag = tag
    @value = value
    super("uncaught throw #{tag.inspect}")
  end
end
