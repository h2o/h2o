class Object
  def to_json
    JSON::stringify(self)
  end
end
