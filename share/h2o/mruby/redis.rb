module H2O

  class Redis
    def initialize(config)
      @config = config
      __setup
    end

    # will be overriden by h2o (define here for passing compile check)
    def __setup; end
    def __connect; end
    def disconnect; end
    def disconnected?; end
    def __call; end

    def password
      @config[:password]
    end

    def db
      @config[:db]
    end

    def db=(_db)
      old = @config[:db]
      @config[:db] = _db.to_i
      if ! disconnected? && @config[:db] != old
        self.select(@config[:db])
      end
    end

    def connect
      __connect
      self.auth(@config[:password]) if @config[:password]
      self.select(@config[:db]) if (@config[:db] || 0) != 0
    end

    def ensure_connected
      connect if disconnected?
      yield
    end

    STREAMING_COMMANDS = %w(subscribe psubscribe).map {|c| [c, true] }.to_h
    NO_REPLY_COMMANDS  = %w(unsubscribe punsubscribe).map {|c| [c, true] }.to_h
    def _command_class(c)
      c = c.to_s.downcase
      if STREAMING_COMMANDS.include?(c)
        Command::Streaming
      elsif NO_REPLY_COMMANDS.include?(c)
        Command::NoReply
      elsif c.to_sym == :exec
        Command::OneShot::Exec
      else
        Command::OneShot
      end
    end

    def call(*command_args, &block)
      command_class = _command_class(command_args[0])
      ensure_connected do
        __call(command_args, command_class, &block)
      end
    end

    # errors
    class BaseError < RuntimeError; end
    class CommandError < BaseError
      attr_reader :command
      def initialize(message, command)
        super("%s (command: %s)" % [message, command.args.join(' ')])
        @command = command
      end
    end
    class ConnectionError < BaseError; end
    class ProtocolError < BaseError; end
    class UnknownError < BaseError; end
    class UnavailableCommandError < BaseError; end

    class Command
      attr_reader :args

      module ReplyReceiver
        def _validate_reply(reply)
          raise reply if reply.kind_of?(RuntimeError)
        end
      end
      include ReplyReceiver

      def initialize(args)
        @args = args
      end


      class OneShot < Command
        def _on_reply(reply)
          @reply = reply
        end
        def join
          if !@reply
            @reply = _h2o__redis_join_reply(self)
          end
          _validate_reply(@reply)
          @reply
        end

        # exec may contain error reply in array reply, or nil reply when watch failed, so have to check it
        class Exec < OneShot
          def _validate_reply(reply)
            if reply.nil?
              raise CommandError.new('transaction was aborted', self)
            end
            super(reply)
            if reply.kind_of?(Array)
              reply.each {|child| super(child) }
            end
          end
        end
      end

      class NoReply < Command
        def _on_reply(reply)
          raise RuntimeError.new('no-reply command got reply: something went wrong?')
        end
        def join
          'OK'
        end
      end

      class Streaming < Command
        class Channel
          include ReplyReceiver
          def initialize(command)
            @command = command
            @replies = []
            @unsubscribed = false
            @error = nil
          end
          def _on_reply(reply)
            @replies << reply
          end
          def shift
            raise @error if @error
            return nil if @replies.empty? && @unsubscribed

            begin
              if @replies.empty?
                reply = _h2o__redis_join_reply(@command)
              else
                reply = @replies.shift
              end
              _validate_reply(reply)
            rescue => e
              @error = e # rethrow this error when called again
              raise e
            end

            kind, channel, message = reply
            if kind == 'unsubscribe'
              return nil
            elsif kind != 'message'
              raise "unexpected kind of message: #{reply[0]}"
            end
            if block_given?
              yield channel, message
            else
              return channel, message
            end
          end
        end

        def initialize(args)
          super(args)
        end
        def _on_reply(reply)
          if @channel
            @channel._on_reply(reply)
          else
            @reply = reply
          end
        end
        def join
          if !@reply
            @reply = _h2o__redis_join_reply(self)
          end
          _validate_reply(@reply)
          unless @reply[0] == 'subscribe'
            raise "unexpected kind of message: #{@reply[0]}"
          end
          @channel = Channel.new(self)
        end
      end
    end

    def _do_block_ensuring(block, &ensuring)
      success = false
      begin
        block.call(self)
        success = true
      rescue ConnectionError => e
        # if connection error happens, discard / unwatch are not needed anymore
        raise e
      ensure
        # to provide original exception information, pass through using ensure, not re-raise.
        # are there more smart ways?
        unless success
          begin
            ensuring.call
          end
        end
      end
    end

    def multi(&block)
      command = call(:MULTI)
      return command unless block
      _do_block_ensuring(block) { discard }
      exec
    end

    def watch(*keys, &block)
      command = call(:WATCH, *keys)
      return command unless block
      _do_block_ensuring(block) { unwatch }
      command
    end

    def quit
      begin
        command = call(:QUIT)
      rescue ConnectionError
        command = Command::NoReply.new
      end

      if block_given?
        yield command
      else
        command
      end
    end

    def monitor
      # monitor command implementation in hiredis asynchronous API is absolutely dangerous, so don't use it!
      raise UnavailableCommandError.new('monitor command is unavailable')
    end

    [
      # Cluster
      %w(
        cluster_addslots cluster_count_failure_reports cluster_countkeysinslot cluster_delslots cluster_failover cluster_forget
        cluster_getkeysinslot cluster_info cluster_keyslot cluster_meet cluster_nodes cluster_replicate
        cluster_reset cluster_saveconfig cluster_set_config_epoch cluster_setslot cluster_slaves cluster_slots
        readonly readwrite
      ),

      # Connection
      %w(
        auth echo ping select swapdb
      ),

      # Generic
      %w(
        del dump exists expire expireat keys
        migrate move object persist pexpire pexpireat
        pttl randomkey rename renamenx restore sort
        touch ttl type unlink wait scan
      ),

      # Geo
      %w(
        geoadd geohash geopos geodist georadius georadiusbymember
      ),

      # Hash
      %w(
        hdel hexists hget hgetall hincrby hincrbyfloat
        hkeys hlen hmget hmset hset hsetnx
        hstrlen hvals hscan
      ),

      # Hyperloglog
      %w(
        pfadd pfcount pfmerge
      ),

      # List
      %w(
        blpop brpop brpoplpush lindex linsert llen
        lpop lpush lpushx lrange lrem lset
        ltrim rpop rpoplpush rpush rpushx
      ),

      # Pubsub
      %w(
        pubsub publish
      ),
      %w(
        psubscribe punsubscribe subscribe unsubscribe
      ),

      # Scripting
      %w(
        eval evalsha script_debug script_exists script_flush script_kill script_load
      ),

      # Server
      %w(
        bgrewriteaof bgsave client_kill client_list client_getname client_pause
        client_reply client_setname command command_count command_getkeys command_info
        config_get config_rewrite config_set config_resetstat dbsize debug_object
        debug_segfault flushall flushdb info lastsave
        role save shutdown slaveof slowlog sync time
      ),

      # Set
      %w(
        sadd scard sdiff sdiffstore sinter sinterstore
        sismember smembers smove spop srandmember srem
        sunion sunionstore sscan
      ),

      # SortedSet
      %w(
        zadd zcard zcount zincrby zinterstore zlexcount
        zrange zrangebylex zrevrangebylex zrangebyscore zrank zrem
        zremrangebylex zremrangebyrank zremrangebyscore zrevrange zrevrangebyscore zrevrank
        zscore zunionstore zscan
      ),

      # String
      %w(
        append bitcount bitfield bitop bitpos decr
        decrby get getbit getrange getset incr
        incrby incrbyfloat mget mset msetnx psetex
        set setbit setex setnx setrange strlen
      ),

      # Transactions
      %w(
        discard exec unwatch
      ),
    ].flatten.each {|method|
      method_args = method.upcase.split(/_/, 2)
      method_args[1].gsub!('_', '-') if method_args[1]
      self.define_method(method) {|*args, &block|
        call(*method_args, *args, &block)
      }
    }

  end

end
