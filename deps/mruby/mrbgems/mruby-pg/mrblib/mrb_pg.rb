module PG
  class Connection
    CONNECT_ARGUMENT_ORDER = %w[host port options tty dbname user password]

    def self.quote_connstr(value)
      return "'" + value.to_s.gsub("'") {|m| '\\' + m } + "'"
    end

    def self.parse_connect_args(*args)
      return '' if args.empty?

      connopts = []

      # Handle an options hash first
      if args.last.is_a?(Hash)
        opthash = args.pop
        opthash.each do |key, val|
          connopts.push("#{key}=#{PG::Connection.quote_connstr(val)}")
        end
      end

      # Option string style
      if args.length == 1 && args.first.to_s.index('=')
        connopts.unshift(args.first)
      else
        args.each_with_index do |val, i|
          next unless val # Skip nil placeholders

          key = CONNECT_ARGUMENT_ORDER[i] or
            raise ArgumentError, "Extra positional parameter %d: %p" % [ i+1, val ]
          connopts.push("#{key}=#{PG::Connection.quote_connstr(val.to_s)}")
        end
      end

      return connopts.join(' ')
    end

    # call-seq:
    #    conn.transaction { |conn| ... } -> result of the block
    # 
    # Executes a +BEGIN+ at the start of the block,
    # and a +COMMIT+ at the end of the block, or
    # +ROLLBACK+ if any exception occurs.
    def transaction(&block)
      res = exec("BEGIN")
      res.check
      block_result = nil
      begin
        block_result = block.call
      rescue Exception
        res = exec("ROLLBACK")
        res.check
        return
      end
      res = exec("COMMIT")
      res.check
      return block_result
    end
  end

  class Result
    def each(&block)
      return to_enum :each unless block_given?

      begin
        idx, length = -1, self.length-1
        while idx < length and length <= self.length and length = self.length-1
          elm = self[idx += 1]
          unless elm
            if elm == nil and length >= self.length
              break
            end
          end
          block.call(elm)
        end
        self
      ensure
        clear
      end
    end
  end
end
