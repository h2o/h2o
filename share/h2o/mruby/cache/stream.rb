module H2O
  class Cache

    class CacheStream
      attr_reader :io, :header
      def initialize(io, header=nil)
        @io = io
        @header = header
        # @hooks = {}
      end
      def version
        @header[:meta]['version']
      end
      def key
        @header[:meta]['key']
      end
      def status
        @header[:meta]['status']
      end
      def reqtime
        @header[:meta]['reqtime']
      end
      def restime
        @header[:meta]['restime']
      end
      def req_headers
        @header[:req_headers]
      end
      def res_headers
        @header[:res_headers]
      end
      def close
        @io.close if @io.respond_to?(:closed)
      end
    end

    class CacheReader < CacheStream
      BUF_SIZE = 4096
      def initialize(io, *args)
        super(io, *args)
      end
      def read(*args)
        io.read(*args)
      end
      def each
        while buf = read(BUF_SIZE) # TODO using io.sysread would be better for performance
          yield buf
        end
      end
      def respond_to_missing?(name, *rest)
        name == :rewind ? io.respond_to?(name, *rest) : false
      end
      def method_missing(name, *rest)
        if name == :rewind && io.respond_to?(name, *rest)
          io.send(name, *rest)
        else
          super(name, *rest)
        end
      end
    end

    class CacheWriter < CacheStream
      attr_accessor :aborted
      def initialize(io, header, *args)
        super(io, header, *args)
        @aborted = false
      end
      def write(buf)
        io.write(buf)
      end
      def flush(body)
        body.each {|buf| write(buf) }
      end
    end

    class TeeStream

      def initialize(input, branch)
        @input = input
        @branch = branch
      end

      def join
        s = ""
        each {|c| s << c }
        s
      end

      def each
        @input.each {|buf|
          unless @branch.nil?
            begin
              @branch.write(buf)
            rescue
              @branch.close if @branch.respond_to?(:close)
              @branch = nil
            end
          end
          yield buf if block_given?
        }
      end

      def close
        @input.close if @input.respond_to?(:close)
        @branch.close if @branch.respond_to?(:close)
      end
    end

  end
end
