# Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto,
#                         Masayoshi Takahashi
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

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
