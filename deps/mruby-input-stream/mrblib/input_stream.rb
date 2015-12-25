class InputStream
  include Enumerable

  #
  # from String#each
  def each(&block)
    self.rewind
    while pos = self.byteindex(0x0a)
      block.call(self.read(pos+1))
    end
    rest = self.read()
    if rest
      block.call(rest)
    end
  end
end
