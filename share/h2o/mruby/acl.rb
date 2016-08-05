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
module H2O

  module ACL

    def acl(&block)
      $ACL += 1
      return ACLBlock.new._to_handler(&block)
    end

    class ACLHandler
      def initialize(p)
        @proc = p
      end
      def call(env)
        return @proc.call(env)
      end
    end

    class ACLBlock

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

      def initialize
        @acl = []
      end

      def _to_handler(&block)
        returned = instance_eval(&block)
        return ACLHandler.new(lambda {|env|
          @acl.each {|ac|
            return ac.call(env) if ac.satisfy?(env)
          }
          return [399, {}, []] if returned.nil?
          return returned.call(env)
        })
      end

      def use(handler, &cond)
        ch = ConditionalHandler.new(handler, cond)
        @acl << ch
        return ch
      end

      def response(status, header={}, body=[], &cond)
        return use(proc {|env| [status, header, body] }, &cond)
      end

      def deny(&cond)
        return response(403, {}, ["Forbidden"], &cond)
      end

      def allow(&cond)
        return response(399, {}, [], &cond)
      end

      def redirect(location, status=302, &cond)
        return response(status, { "Location" => location }, [], &cond)
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


