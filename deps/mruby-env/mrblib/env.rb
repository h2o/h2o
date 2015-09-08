class << ENV
  alias include? has_key?
  alias key? has_key?
  alias member? has_key?

  def clear
    self.keys.each { |k| self.delete(k) }
    self
  end

  def delete(key)
    old = self[key]
    self[key] = nil
    old
  end
end
