class Object
  def to_json()
    JSON::generate(self)
  end
end

module JSON
  class JSONError < StandardError; end
  class ParserError < JSONError; end
end
