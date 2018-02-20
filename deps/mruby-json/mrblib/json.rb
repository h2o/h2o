class Object
  def to_json()
    JSON::generate(self)
  end
end
