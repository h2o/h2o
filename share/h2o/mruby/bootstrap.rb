module H2O

  @@hooks = {
    :after_generate_handler => [],
  }

  def self.after_generate_handler(handler)
    _call_hooks(:after_generate_handler, handler)
  end

  def self.add_after_generate_handler_hook(hook)
    _add_hook(:after_generate_handler, hook)
  end

  def self._call_hooks(type, *args)
    @@hooks[type].each {|hook| hook.call(*args) }
    @@hooks[type].clear
  end

  def self._add_hook(type, hook)
    @@hooks[type] << hook
  end

end
