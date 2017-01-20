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
    pendings = []
    app = Proc.new do |req|
      pendings.push([Fiber.current, req])
      Fiber.yield([-5])
    end

    cached = nil
    runner = Proc.new do |args|
      req, generator = *args
      fiber = cached || Fiber.new do |req|
        self_fiber = Fiber.current
        while 1
          begin
            while 1
              resp = app.call(req)
              cached = self_fiber
              req = Fiber.yield(*resp, generator)
            end
          rescue => e
            cached = self_fiber
            req = Fiber.yield([-1, e, generator])
          end
        end
      end
      cached = nil
      fiber.resume(req)
    end

    configurer = Proc.new do
      fiber = Fiber.new do
        begin
          app = conf_proc.call
        rescue => e
          app = Proc.new do |req|
            [500, {}, ['Internal Server Error']]
          end
          raise e
        end

        if !pendings.empty?
          pendings.each do |pending|
            # FIXME: this doesn't work!
            pendings[0].resume(pendings[1])
          end
          pendings.clear
        end
        [-6]
      end
      fiber.resume
    end

    [runner, configurer]
  end

end
