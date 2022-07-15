class Symbol
  def to_proc
    ->(obj,*args,**opts,&block) do
      obj.__send__(self, *args, **opts, &block)
    end
  end
end
