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


