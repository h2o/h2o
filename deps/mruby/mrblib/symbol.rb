class Symbol
  def to_proc
    ->(obj,*args,&block) do
      obj.__send__(self, *args, &block)
    end
  end
end
