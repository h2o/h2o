##
# Hash
#
# ISO 15.2.13
class Hash
  ##
  #  Equality---Two hashes are equal if they each contain the same number
  #  of keys and if each key-value pair is equal to (according to
  #  <code>Object#==</code>) the corresponding elements in the other
  #  hash.
  #
  # ISO 15.2.13.4.1
  def ==(hash)
    return true if self.equal?(hash)
    begin
      hash = hash.to_hash
    rescue NoMethodError
      return false
    end
    return false if self.size != hash.size
    self.each do |k,v|
      return false unless hash.key?(k)
      return false unless self[k] == hash[k]
    end
    return true
  end

  ##
  # Returns <code>true</code> if <i>hash</i> and <i>other</i> are
  # both hashes with the same content compared by eql?.
  #
  # ISO 15.2.13.4.32 (x)
  def eql?(hash)
    return true if self.equal?(hash)
    begin
      hash = hash.to_hash
    rescue NoMethodError
      return false
    end
    return false if self.size != hash.size
    self.each do |k,v|
      return false unless hash.key?(k)
      return false unless self[k].eql?(hash[k])
    end
    return true
  end

  ##
  # Delete the element with the key +key+.
  # Return the value of the element if +key+
  # was found. Return nil if nothing was
  # found. If a block is given, call the
  # block with the value of the element.
  #
  # ISO 15.2.13.4.8
  def delete(key, &block)
    if block && !self.has_key?(key)
      block.call(key)
    else
      self.__delete(key)
    end
  end

  ##
  # Calls the given block for each element of +self+
  # and pass the key and value of each element.
  #
  # call-seq:
  #   hsh.each      {| key, value | block } -> hsh
  #   hsh.each_pair {| key, value | block } -> hsh
  #   hsh.each                              -> an_enumerator
  #   hsh.each_pair                         -> an_enumerator
  #
  #
  # If no block is given, an enumerator is returned instead.
  #
  #     h = { "a" => 100, "b" => 200 }
  #     h.each {|key, value| puts "#{key} is #{value}" }
  #
  # <em>produces:</em>
  #
  # a is 100
  # b is 200
  #
  # ISO 15.2.13.4.9
  def each(&block)
    return to_enum :each unless block_given?

    keys = self.keys
    vals = self.values
    len = self.size
    i = 0
    while i < len
      block.call [keys[i], vals[i]]
      i += 1
    end
    self
  end

  ##
  # Calls the given block for each element of +self+
  # and pass the key of each element.
  #
  # call-seq:
  #   hsh.each_key {| key | block } -> hsh
  #   hsh.each_key                  -> an_enumerator
  #
  # If no block is given, an enumerator is returned instead.
  #
  #   h = { "a" => 100, "b" => 200 }
  #   h.each_key {|key| puts key }
  #
  # <em>produces:</em>
  #
  #  a
  #  b
  #
  # ISO 15.2.13.4.10
  def each_key(&block)
    return to_enum :each_key unless block_given?

    self.keys.each{|k| block.call(k)}
    self
  end

  ##
  # Calls the given block for each element of +self+
  # and pass the value of each element.
  #
  # call-seq:
  #   hsh.each_value {| value | block } -> hsh
  #   hsh.each_value                    -> an_enumerator
  #
  # If no block is given, an enumerator is returned instead.
  #
  #  h = { "a" => 100, "b" => 200 }
  #  h.each_value {|value| puts value }
  #
  # <em>produces:</em>
  #
  #  100
  #  200
  #
  # ISO 15.2.13.4.11
  def each_value(&block)
    return to_enum :each_value unless block_given?

    self.keys.each{|k| block.call(self[k])}
    self
  end

  ##
  # Replaces the contents of <i>hsh</i> with the contents of other hash
  #
  # ISO 15.2.13.4.23
  def replace(hash)
    raise TypeError, "can't convert argument into Hash" unless hash.respond_to?(:to_hash)
    self.clear
    hash = hash.to_hash
    hash.each_key{|k|
      self[k] = hash[k]
    }
    if hash.default_proc
      self.default_proc = hash.default_proc
    else
      self.default = hash.default
    end
    self
  end
  # ISO 15.2.13.4.17
  alias initialize_copy replace

  ##
  # Return a hash which contains the content of
  # +self+ and +other+. If a block is given
  # it will be called for each element with
  # a duplicate key. The value of the block
  # will be the final value of this element.
  #
  # ISO 15.2.13.4.22
  def merge(other, &block)
    h = {}
    raise TypeError, "can't convert argument into Hash" unless other.respond_to?(:to_hash)
    other = other.to_hash
    self.each_key{|k| h[k] = self[k]}
    if block
      other.each_key{|k|
        h[k] = (self.has_key?(k))? block.call(k, self[k], other[k]): other[k]
      }
    else
      other.each_key{|k| h[k] = other[k]}
    end
    h
  end

  # internal method for Hash inspection
  def _inspect
    return "{}" if self.size == 0
    "{"+self.map {|k,v|
      k._inspect + "=>" + v._inspect
    }.join(", ")+"}"
  end
  ##
  # Return the contents of this hash as a string.
 #
  # ISO 15.2.13.4.30 (x)
  def inspect
    begin
      self._inspect
    rescue SystemStackError
      "{...}"
    end
  end
  # ISO 15.2.13.4.31 (x)
  alias to_s inspect

  ##
  #  call-seq:
  #     hsh.reject! {| key, value | block }  -> hsh or nil
  #     hsh.reject!                          -> an_enumerator
  #
  #  Equivalent to <code>Hash#delete_if</code>, but returns
  #  <code>nil</code> if no changes were made.
  #
  #  1.8/1.9 Hash#reject! returns Hash; ISO says nothing.
  #
  def reject!(&b)
    return to_enum :reject! unless block_given?

    keys = []
    self.each{|k,v|
      if b.call([k, v])
        keys.push(k)
      end
    }
    return nil if keys.size == 0
    keys.each{|k|
      self.delete(k)
    }
    self
  end

  ##
  #  call-seq:
  #     hsh.reject {|key, value| block}   -> a_hash
  #     hsh.reject                        -> an_enumerator
  #
  #  Returns a new hash consisting of entries for which the block returns false.
  #
  #  If no block is given, an enumerator is returned instead.
  #
  #     h = { "a" => 100, "b" => 200, "c" => 300 }
  #     h.reject {|k,v| k < "b"}  #=> {"b" => 200, "c" => 300}
  #     h.reject {|k,v| v > 100}  #=> {"a" => 100}
  #
  #  1.8/1.9 Hash#reject returns Hash; ISO says nothing.
  #
  def reject(&b)
    return to_enum :reject unless block_given?

    h = {}
    self.each{|k,v|
      unless b.call([k, v])
        h[k] = v
      end
    }
    h
  end

  ##
  #  call-seq:
  #     hsh.select! {| key, value | block }  -> hsh or nil
  #     hsh.select!                          -> an_enumerator
  #
  #  Equivalent to <code>Hash#keep_if</code>, but returns
  #  <code>nil</code> if no changes were made.
  #
  #  1.9 Hash#select! returns Hash; ISO says nothing.
  #
  def select!(&b)
    return to_enum :select! unless block_given?

    keys = []
    self.each{|k,v|
      unless b.call([k, v])
        keys.push(k)
      end
    }
    return nil if keys.size == 0
    keys.each{|k|
      self.delete(k)
    }
    self
  end

  ##
  #  call-seq:
  #     hsh.select {|key, value| block}   -> a_hash
  #     hsh.select                        -> an_enumerator
  #
  #  Returns a new hash consisting of entries for which the block returns true.
  #
  #  If no block is given, an enumerator is returned instead.
  #
  #     h = { "a" => 100, "b" => 200, "c" => 300 }
  #     h.select {|k,v| k > "a"}  #=> {"b" => 200, "c" => 300}
  #     h.select {|k,v| v < 200}  #=> {"a" => 100}
  #
  #  1.9 Hash#select returns Hash; ISO says nothing
  #
  def select(&b)
    return to_enum :select unless block_given?

    h = {}
    self.each{|k,v|
      if b.call([k, v])
        h[k] = v
      end
    }
    h
  end

  ##
  #  call-seq:
  #    hsh.rehash -> hsh
  #
  #  Rebuilds the hash based on the current hash values for each key. If
  #  values of key objects have changed since they were inserted, this
  #  method will reindex <i>hsh</i>.
  #
  #     h = {"AAA" => "b"}
  #     h.keys[0].chop!
  #     h          #=> {"AA"=>"b"}
  #     h["AA"]    #=> nil
  #     h.rehash   #=> {"AA"=>"b"}
  #     h["AA"]    #=> "b"
  #
  def rehash
    h = {}
    self.each{|k,v|
      h[k] = v
    }
    self.replace(h)
  end

  def __update(h)
    h.each_key{|k| self[k] = h[k]}
    self
  end
end

##
# Hash is enumerable
#
# ISO 15.2.13.3
class Hash
  include Enumerable
end
