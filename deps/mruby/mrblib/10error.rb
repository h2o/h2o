# ISO 15.2.24
class ArgumentError < StandardError
end

# ISO 15.2.25 says "LocalJumpError < StandardError"
class LocalJumpError < ScriptError
end

# ISO 15.2.26
class RangeError < StandardError
end

class FloatDomainError < RangeError
end

# ISO 15.2.26
class RegexpError < StandardError
end

# ISO 15.2.29
class TypeError < StandardError
end

# ISO 15.2.31
class NameError < StandardError
  attr_accessor :name

  def initialize(message=nil, name=nil)
    @name = name
    super(message)
  end
end

# ISO 15.2.32
class NoMethodError < NameError
  attr_reader :args

  def initialize(message=nil, name=nil, args=nil)
    @args = args
    super message, name
  end
end

# ISO 15.2.33
class IndexError < StandardError
end

class KeyError < IndexError
end

class NotImplementedError < ScriptError
end

class FrozenError < RuntimeError
end

class StopIteration < IndexError
  attr_accessor :result
end
