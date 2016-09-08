# Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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
#
require "bootstrap.rb"

module H2O

  module ACL

    def acl(&block)
      context = H2O::ConfigurationContext.instance
      if context.get_value(:acl_handler) then
        raise "acl can be called only once for each handler configuration"
      end
      acl_handler = ACLHandler.new(&block)
      context.set_value(:acl_handler, acl_handler)
      context.add_post_handler_generation_hook(proc {|handler|
        if handler != acl_handler
          raise "acl configuration is ignored"
        end
      })
      return acl_handler
    end

    class ACLHandler

      class ConditionalHandler
        def initialize(handler, cond)
          @handler = handler
          @cond = cond
        end

        def satisfy?(env)
           return @cond.nil? || MatchingBlock.new(env).instance_eval(&@cond)
        end

        def call(env)
          return @handler.call(env) if satisfy?(env)
          return [399, {}, []]
        end
      end

      def initialize(&block)
        @acl = []
        instance_eval(&block)
      end

      def call(env)
        @acl.each {|ac|
          return ac.call(env) if ac.satisfy?(env)
        }
        return [399, {}, []]
      end

      def use(handler, &cond)
        ch = ConditionalHandler.new(handler, cond)
        @acl << ch
      end

      def respond(status, header={}, body=[], &cond)
        use(proc {|env| [status, header, body] }, &cond)
      end

      def deny(&cond)
        respond(403, {}, ["Forbidden"], &cond)
      end

      def allow(&cond)
        respond(399, {}, [], &cond)
      end

      def redirect(location, status=302, &cond)
        respond(status, { "Location" => location }, [], &cond)
      end

      class MatchingBlock
        def initialize(env)
          @env = env
        end

        def addr(forwarded=true)
          addr = @env['REMOTE_ADDR']
          if forwarded && (xff = @env['HTTP_X_FORWARDED_FOR'])
            xaddr = xff.split(",")[0]
            addr = xaddr if xaddr
          end
          return addr || ""
        end

        def path
          return @env["PATH_INFO"] || ""
        end

        def method
          return @env["REQUEST_METHOD"] || ""
        end

        def header(name)
          name = 'HTTP_' + name.gsub(/-/, '_').upcase;
          return @env[name] || ""
        end

        def user_agent
          return header("User-Agent") || ""
        end

      end

    end

  end

end
