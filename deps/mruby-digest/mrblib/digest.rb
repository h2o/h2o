if Object.const_defined? :Digest
module Digest
  class Base
    def self.digest(data)
      self.new.update(data).digest
    end
    def self.file(path)
      self.new.update(File.open(path).read)
    end
    def self.hexdigest(data)
      self.new.update(data).hexdigest
    end
    def ==(other)
      if other.kind_of? String
        self.hexdigest == other
      else 
        self.digest == other.digest
      end
    end
    def file(path)
      self.update(File.open(path).read)
    end
    def hexdigest!
      x = self.hexdigest
      self.reset
      x
    end

    alias length digest_length
    alias size digest_length
    alias to_s hexdigest
    alias << update
  end

  class HMAC
    def self.digest(data, key, digest)
      self.new(key, digest).update(data).digest
    end
    def self.hexdigest(data, key, digest)
      self.new(key, digest).update(data).hexdigest
    end

    alias << update
  end
end
end
