module Kernel

  def _h2o_define_callback(name, id)
    Kernel.define_method(name) do |*args|
      ret = Fiber.yield([ id, _h2o_create_resumer(), args ])
      if ret.kind_of? Exception
        raise ret
      end
      ret
    end
  end

  def _h2o_create_resumer()
    me = Fiber.current
    Proc.new do |v|
    me.resume(v)
    end
  end

  def _h2o_proc_each_to_array()
    Proc.new do |o|
      a = []
      o.each do |x|
        a << x
      end
      a
    end
  end

  def _h2o_proc_app_to_fiber()
    Proc.new do |app|
      cached = nil
      Proc.new do |req|
        fiber = cached
        cached = nil
        if !fiber
          fiber = Fiber.new do
            self_fiber = Fiber.current
            req = Fiber.yield
            while 1
              begin
                while 1
                  resp = app.call(req)
                  cached = self_fiber
                  req = Fiber.yield(resp)
                end
              rescue => e
                cached = self_fiber
                req = Fiber.yield([-1, e])
              end
            end
          end
          fiber.resume
        end
        fiber.resume(req)
      end
    end
  end

end
