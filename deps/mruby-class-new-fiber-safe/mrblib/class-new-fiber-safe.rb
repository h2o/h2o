class Class
  def new(*args, &block)
    obj = self.allocate
    obj.initialize(*args, &block)
    obj
  end
end
