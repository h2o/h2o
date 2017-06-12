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
        command
      end
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

    def multi
      res = call(:MULTI)
      if ! block_given?
        return res
      end

      begin
        yield self
      # FIXME
      # rescue ConnectionError => e
      #   raise
      rescue StandardError => e
        discard
        raise e
      end

      call(:exec)
    end

    def watch(*keys)
      res = call(:WATCH, *keys)
      if !block_given?
        return res
      end

      begin
        yield self
      # FIXME
      # rescue ConnectionError => e
      #   raise
      rescue StandardError => e
        unwatch
        raise e
      end
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
        auth echo ping quit select swapdb
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
        psubscribe pubsub publish punsubscribe subscribe unsubscribe
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
        debug_segfault flushall flushdb info lastsave monitor
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
      method_args = method_args = method.upcase.split(/_/, 2)
      method_args[1].gsub!('_', '-') if method_args[1]
      self.define_method(method) {|*args|
        call(*method_args, *args)
      }
    }

  end

end
