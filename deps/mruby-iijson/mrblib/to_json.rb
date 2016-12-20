class Array
  def to_json
    JSON.generate(self)
  end
end

class FalseClass
  def to_json
    JSON.generate(self)
  end
end

class Fixnum
  def to_json
    JSON.generate(self)
  end
end

class Float
  def to_json
    JSON.generate(self)
  end
end

class Hash
  def to_json
    JSON.generate(self)
  end
end

class NilClass
  def to_json
    JSON.generate(self)
  end
end

class String
  def to_json
    JSON.generate(self)
  end
end

class TrueClass
  def to_json
    JSON.generate(self)
  end
end
