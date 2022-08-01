##
# Hash
#
# ISO 15.2.13
class Hash
  ##
  # Hash is enumerable
  #
  # ISO 15.2.13.3
  include Enumerable

  ##
  # call-seq:
  #   hash == object -> true or false
  #
  #  Equality---Two hashes are equal if they each contain the same number
  #  of keys and if each key-value pair is equal to (according to
  #  <code>Object#==</code>) the corresponding elements in the other
  #  hash.
  #
  # ISO 15.2.13.4.1
  def ==(hash)
    return true if self.equal?(hash)
    unless Hash === hash
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
  # call-seq:
  #   hash.eql? object -> true or false
  #
  # Returns <code>true</code> if <i>hash</i> and <i>other</i> are
  # both hashes with the same content compared by eql?.
  #
  # ISO 15.2.13.4.32 (x)
  def eql?(hash)
    return true if self.equal?(hash)
    unless Hash === hash
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
  # call-seq:
  #   hash.delete(key) -> value or nil
  #   hash.delete(key) {|key| ... } -> object
  #
  # Delete the element with the key +key+.
  # Return the value of the element if +key+
  # was found. Return nil if nothing was
  # found. If a block is given, call the
  # block with the value of the element.
  #
  # ISO 15.2.13.4.8
  def delete(key, &block)
    if block && !self.has_key?(key)
      return block.call(key)
    end
    self.__delete(key)
  end

  ##
  # call-seq:
  #   hsh.each      {| key, value | block } -> hsh
  #   hsh.each_pair {| key, value | block } -> hsh
  #   hsh.each                              -> an_enumerator
  #   hsh.each_pair                         -> an_enumerator
  #
  # Calls the given block for each element of +self+
  # and pass the key and value of each element.
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
    return to_enum :each unless block

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
  # call-seq:
  #   hsh.each_key {| key | block } -> hsh
  #   hsh.each_key                  -> an_enumerator
  #
  # Calls the given block for each element of +self+
  # and pass the key of each element.
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
    return to_enum :each_key unless block

    self.keys.each{|k| block.call(k)}
    self
  end

  ##
  # call-seq:
  #   hsh.each_value {| value | block } -> self
  #   hsh.each_value                    -> an_enumerator
  #
  # Calls the given block with each value; returns +self+:
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
    return to_enum :each_value unless block

    self.values.each{|v| block.call(v)}
    self
  end

  ##
  # call-seq:
  #     hsh.merge(other_hash..)                                 -> hsh
  #     hsh.merge(other_hash..){|key, oldval, newval| block}    -> hsh
  #
  #  Returns the new \Hash formed by merging each of +other_hashes+
  #  into a copy of +self+.
  #
  #  Each argument in +other_hashes+ must be a \Hash.
  #  Adds the contents of _other_hash_ to _hsh_.  If no block is specified,
  #  entries with duplicate keys are overwritten with the values from
  #  _other_hash_, otherwise the value of each duplicate key is determined by
  #  calling the block with the key, its value in _hsh_ and its value in
  #  _other_hash_.
  #
  #  Example:
  #   h = {foo: 0, bar: 1, baz: 2}
  #   h1 = {bat: 3, bar: 4}
  #   h2 = {bam: 5, bat:6}
  #   h3 = h.merge(h1, h2) { |key, old_value, new_value| old_value + new_value }
  #   h3 # => {:foo=>0, :bar=>5, :baz=>2, :bat=>9, :bam=>5}
  #
  # ISO 15.2.13.4.22
  def merge(*others, &block)
    i=0; len=others.size
    h = self.dup
    return h.__merge(*others) unless block
    while i<len
      other = others[i]
      i += 1
      raise TypeError, "Hash required (#{other.class} given)" unless Hash === other
      other.each_key{|k|
        h[k] = (self.has_key?(k))? block.call(k, self[k], other[k]): other[k]
      }
    end
    h
  end

  # internal method for Hash inspection
  def _inspect(recur_list)
    return "{}" if self.size == 0
    return "{...}" if recur_list[self.object_id]
    recur_list[self.object_id] = true
    ary=[]
    keys=self.keys
    vals=self.values
    size=keys.size
    i=0
    while i<size
      ary<<(keys[i]._inspect(recur_list) + "=>" + vals[i]._inspect(recur_list))
      i+=1
    end
    "{"+ary.join(", ")+"}"
  end
  ##
  # Return the contents of this hash as a string.
  #
  # ISO 15.2.13.4.30 (x)
  def inspect
    self._inspect({})
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
  def reject!(&block)
    return to_enum :reject! unless block

    keys = []
    self.each{|k,v|
      if block.call([k, v])
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
  def reject(&block)
    return to_enum :reject unless block

    h = {}
    self.each{|k,v|
      unless block.call([k, v])
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
  def select!(&block)
    return to_enum :select! unless block

    keys = []
    self.each{|k,v|
      unless block.call([k, v])
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
  def select(&block)
    return to_enum :select unless block

    h = {}
    self.each{|k,v|
      if block.call([k, v])
        h[k] = v
      end
    }
    h
  end
end
