module H2O

  class ConfigurationContext
    def self.instance()
      @@instance
    end
    def self.reset()
      @@instance = self.new()
    end
    def initialize()
      @values = {}
      @post_handler_generation_hooks = []
    end
    def get_value(key)
      @values[key]
    end
    def set_value(key, value)
      @values[key] = value
    end
    def delete_value(key)
      @values[key].delete
    end
    def add_post_handler_generation_hook(hook)
      @post_handler_generation_hooks << hook
    end
    def call_post_handler_generation_hooks(handler)
      @post_handler_generation_hooks.each {|hook| hook.call(handler) }
    end
  end

  # TODO: embed in c code
  def self.prepare_app(conf_proc)
    app = Proc.new do |req|
      Fiber.yield([-5])
    end

    cached = nil
    runner = Proc.new do |args|
      fiber = cached || Fiber.new do |req, generator|
        self_fiber = Fiber.current
        while 1
          begin
            while 1
              resp = app.call(req)
              cached = self_fiber
              (req, generator) = Fiber.yield(*resp, generator)
            end
          rescue => e
            cached = self_fiber
            (req, generator) = Fiber.yield([-1, e, generator])
          end
        end
      end
      cached = nil
      fiber.resume(*args)
    end

    configurer = Proc.new do
      fiber = Fiber.new do
        e = nil
        begin
          app = conf_proc.call
        rescue => e
          app = Proc.new do |req|
            [500, {}, ['Internal Server Error']]
          end
        end
        [-6, e]
      end
      fiber.resume
    end

    [runner, configurer]
  end

end
