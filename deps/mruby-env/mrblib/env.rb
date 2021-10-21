class << ENV
  NONE = Object.new

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

  def fetch(key, default = NONE, &block)
    if key?(key)
      self[key]
    elsif block
      block.call(key)
    elsif default != NONE
      default
    else
      raise KeyError, "key not found: #{key}"
    end
  end
end
