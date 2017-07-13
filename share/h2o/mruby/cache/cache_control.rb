module H2O
  class Cache
    class CacheControl
      DIRECTIVES = {
        :'max-age'          => { :argtype => :int },
        :'s-maxage'         => { :argtype => :int },
        :'max-stale'        => { :argtype => :int },
        :'min-fresh'        => { :argtype => :int },
        :'no-cache'         => { },
        :'no-store'         => { },
        :'no-transform'     => { },
        :'only-if-cached'   => { },
        :'must-revalidate'  => { },
        :'public'           => { },
        :'private'          => { },
        :'proxy-revalidate' => { },
      }

      def initialize(value=nil)
        @hash = CacheControl.parse_string(value)
      end

      def max_age
        @hash[:'max-age']
      end
      def s_max_age
        @hash[:'s-maxage']
      end
      def max_stale
        @hash[:'max-stale']
      end
      def max_fresh
        @hash[:'max-fresh']
      end
      def no_cache?
        @hash[:'no-cache'] end
      def no_store?
        @hash[:'no-store']
      end
      def no_transform?
        @hash[:'no-transform']
      end
      def only_if_cached?
        @hash[:'no-transform']
      end
      def must_revalidate?
        @hash[:'must-revalidate']
      end
      def public?
        @hash[:'public']
      end
      def private?
        @hash[:'private']
      end
      def proxy_revalidate?
        @hash[:'proxy-revalidate']
      end

      def to_s
        @hash.keys.sort.map {|name|
          @hash[name] == true ? name : "#{name}=#{@hash[name]}"
        }.join(', ')
      end

      def self.parse_string(str)
        hash = {}
        return hash if str.nil? || str.empty?
        str.gsub(' ', '').split(',').each do |part|
          next if part.empty?
          name, value = part.split('=', 2)
          name.downcase!
          name = name.to_sym
          directive = DIRECTIVES[name] or next
          if value.nil?
            value = true
          else
            value = value[1..-2] if value[0] == '"' && value[-1] == '"'
            value = value.to_i if directive[:argtype] == :int
          end
          hash[name] = value
        end
        hash
      end

    end
  end
end
