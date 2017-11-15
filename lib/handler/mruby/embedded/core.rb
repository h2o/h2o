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

$__TOP_SELF__ = self
def _h2o_eval_conf(__h2o_conf)
  $__TOP_SELF__.eval(__h2o_conf[:code], nil, __h2o_conf[:file], __h2o_conf[:line])
end

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

  H2O_CALLBACK_ID_EXCEPTION_RAISED = -1
  H2O_CALLBACK_ID_CONFIGURING_APP = -2
  H2O_CALLBACK_ID_CONFIGURED_APP = -3
  def _h2o_prepare_app(conf)
    app = Proc.new do |req|
      [H2O_CALLBACK_ID_CONFIGURING_APP]
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
            (req, generator) = Fiber.yield([H2O_CALLBACK_ID_EXCEPTION_RAISED, e, generator])
          end
        end
      end
      cached = nil
      fiber.resume(*args)
    end

    configurator = Proc.new do
      fiber = Fiber.new do
        begin
          H2O::ConfigurationContext.reset
          app = _h2o_eval_conf(conf)
          H2O::ConfigurationContext.instance.call_post_handler_generation_hooks(app)
          [H2O_CALLBACK_ID_CONFIGURED_APP]
        rescue => e
          app = Proc.new do |req|
            [500, {}, ['Internal Server Error']]
          end
          [H2O_CALLBACK_ID_CONFIGURED_APP, e]
        end
      end
      fiber.resume
    end

    [runner, configurator]
  end

  def sleep(*sec)
    _h2o__sleep(*sec)
  end

end

module H2O

  class App
    def call(env)
      _h2o_delegate(env, false)
    end
    def reprocess(env)
      _h2o_delegate(env, true)
    end
  end

  class << self
    @@app = App.new
    def app
      @@app
    end
  end

  class DelegateInputStream
    def initialize
      @chunks = []
      @finished = false
    end
    def each
      loop do
        while c = @chunks.shift
          yield c
        end
        break if @finished
        _h2o_delegate_wait_chunk(self)
      end
    end
    def join
      s = ""
      each do |c|
        s << c
      end
      s
    end
  end
end

