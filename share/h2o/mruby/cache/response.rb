require 'rack'
require 'time'
require 'cache/cache_control'

module H2O
  class Cache
    class Response

      attr_accessor :status, :headers, :body, :time
      attr_reader :req, :now

      def initialize(req, status, headers, body, options = {})
        @req = req
        @status = status.to_i
        @headers = Rack::Utils::HeaderHash.new(headers)
        @body = body
        @options = options
        @now = Time.now
        @time = options[:time] ? Time.at(options[:time]) : @now
      end

      def to_a
        [status, headers.to_hash, body]
      end

      def cache_control
        @cache_control ||= CacheControl.new(headers['Cache-Control'])
      end
      def no_cache?
        cache_control.no_cache?
      end

      def max_age
        @max_age ||=
          cache_control.s_max_age ||
            cache_control.max_age ||
             (expires && (expires - date))
      end

      def date
        @date ||=
          if date = headers['Date']
            begin
              Time.imf_fixdate(date)
            rescue ArgumentError
              time
            end
          else
            time
          end
      end

      # https://tools.ietf.org/html/rfc7234#section-4.2.3
      def age
        @age ||= begin
          apparent_age = [0, time - date].max
          response_delay = time - req.time
          corrected_age_value = headers['Age'].to_i + response_delay
          corrected_initial_age = [apparent_age, corrected_age_value].max
          resident_time = now - time
          current_age = corrected_initial_age + resident_time
          current_age.to_i
        end
      end

      def ttl
        @ttl ||=
          if ttl = @options[:ttl]
            ttl = ttl.call(self) if ttl.respond_to?(:call)
            ttl -= (@now - @time)
            ttl
          elsif ma = max_age
            ma - age
          elsif default_ttl = @options[:default_ttl]
            default_ttl = default_ttl.call(self) if default_ttl.respond_to?(:call)
            default_ttl -= (@now - @time)
            default_ttl
          else
            0
          end
      end

      def expires
        @expires ||=
          if value = headers['Expires']
            Time.imf_fixdate(value)
          end
      rescue ArgumentError
        nil
      end

      def last_modified
        @last_modified ||=
          if value = headers['Last-Modified']
            Time.imf_fixdate(value)
          end
      rescue ArgumentError
        nil
      end

      def etag
        headers['ETag']
      end

      # https://tools.ietf.org/html/rfc7232#section-4.1
      NOT_MODIFIED_HEADERS = ['Cache-Control', 'Content-Location', 'Date', 'ETag', 'Expires', 'Last-Modified', 'Vary'].map {|h| [h, true] }.to_h

      def not_modified!
        @status = 304
        @headers.keys.each {|k| @headers.delete(k) unless NOT_MODIFIED_HEADERS.include?(k) }
        empty_body!
      end

      def empty_body!
        if @body.respond_to?(:close)
          @body.close
          @body = []
        end
      end

    end
  end
end
