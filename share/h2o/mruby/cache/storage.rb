require 'cache/stream'

module H2O

  class Cache

    class Storage
      def initialize(options={})
        @options = options
      end
      def lookup(req)
        return nil unless reader = reader(req)
        if block_given?
          yield reader
        else
          Response.new(req, reader.status, reader.res_headers, reader)
        end
      end
      def store(res, options = {})
        writer = writer(res)
        writer.flush(res.body) if res.body
        writer.close

        if res.body
          rewind = options.key?(:rewind) ? options[:rewind] : true
          if rewind
            if res.body.respond_to?(:rewind)
              res.body.rewind
            else
              res.body.close if res.body.respond_to?(:close)
              res.body = reader(res.req) # reopen
            end
          end
        end

        res
      end
      def tee(res)
        res.body = TeeStream.new(res.body, writer(res))
        res
      end
      def writer(res)
        raise NotImplementedError
      end
      def reader(req)
        raise NotImplementedError
      end
    end

    class Disk < Storage
      CACHE_VERSION = 1

      class DiskReader < CacheReader
        def initialize(path)
          file = File.open(path, 'r')
          super(file)
          @header = [:meta, :req_headers, :res_headers].map{|k| [k, JSON.parse(file.readline)] }.to_h
        end
        def path
          io.path
        end
      end

      class DiskWriter < CacheWriter
        attr_reader :path, :temp_path
        def initialize(path, header)
          @path = path
          @temp_path = @path + '.temp' # FIXME assign unique filename
          prepare_dir(@temp_path)
          file = File.open(@temp_path, 'w', 0600)
          super(file, header)

          file.puts(JSON.generate(header[:meta]), JSON.generate(header[:req_headers]), JSON.generate(header[:res_headers]))
        end

        def close
          super
          if aborted
            begin
              File.delete(temp_path) if File.exist?(temp_path)
            rescue
            end
          else
            begin
              File.rename(temp_path, path) if File.exist?(temp_path)
            rescue => e
              begin
                File.delete(temp_path) if File.exist?(temp_path)
              rescue
              end
              raise e
            end
          end
        end

        def prepare_dir(file_path)
          dir = File.dirname(file_path)
          stack = []
          until Dir.exist?(dir)
            stack.push(dir)
            dir = File.dirname(dir)
          end
          stack.reverse_each do |path|
            begin
              Dir.mkdir path, 0700
            rescue SystemCallError => e
              raise e unless Dir.exist?(path)
            end
          end
          stack[0]
        end

      end

      def initialize(dir, options={})
        super(options)
        @dir = dir
      end

      def reader(req)
        key = req.url
        file_path = file_path(req.url) # TODO use cache_key lambda
        if !File.exist?(file_path)
          return nil
        end

        reader = DiskReader.new(file_path)

        # TODO vary header?
        unless reader.key == key && reader.version == CACHE_VERSION
          reader.close
          return nil
        end

        reader
      end

      def writer(res)
        key = res.req.url # TODO use cache_key lambda
        file_path = file_path(key)
        meta = {
          "version"     => CACHE_VERSION,
          "key"         => key,
          "status"      => res.status,
          "reqtime"     => res.req.time.to_f,
          "restime"     => res.time.to_f,
          # "valid_until" => valid_until,
        }
        req_headers = res.req.headers.to_h
        res_headers = res.headers.to_h

        return DiskWriter.new(
            file_path,
            { :meta => meta, :req_headers => req_headers, :res_headers => res_headers },
        )
      end

      def file_path(url)
        md5hex = Digest::MD5.hexdigest(url);
        level1 = md5hex[-1]
        level2 = md5hex[-3, 2]
        return File.join(@dir, level1, level2, md5hex)
      end

    end


  end

end
