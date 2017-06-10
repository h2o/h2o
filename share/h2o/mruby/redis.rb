module H2O

  class Redis

    def initialize(config)
      @config = config
      __setup
    end

    # will be overriden by h2o (define here for passing compile check)
    def __setup; end
    def connect; end
    def disconnect; end
    def __call; end

    def ensure_connected
      # TODO: retry?
      connect
      yield
    end

    def call(*command_args)
      ensure_connected do
        command = __call(command_args)
        command.args = command_args
      end
    end

    def get(key)
      call(:get, key)
    end

    def set(key, value, options = {})
      command = [:set, key, value]

      ex = options[:ex]
      command.concat(['EX', ex]) if ex

      px = options[:px]
      command.concat(['PX', px]) if px

      nx = options[:nx]
      command.concat(['NX']) if nx

      xx = options[:xx]
      command.concat(['XX']) if xx

      call(*command)
    end

    def del(*keys)
      call(:del, *keys)
    end

    class CommandError < RuntimeError
      attr_reader :command
      def initialize(message, command)
        super("%s (command: %s)" % [message, command.args.join(' ')])
        @command = command
      end
    end

    class Command
      attr_accessor :args
      def _set_reply(reply)
        @reply = reply
      end
      def join
        if !@reply
          begin
            @reply = _h2o__redis_join_reply(self)
          rescue RuntimeError => e
            @reply = e
          end
        end
        if @reply.kind_of?(RuntimeError)
          raise CommandError.new(@reply.message, self)
        end
        @reply
      end
    end

  end

end
