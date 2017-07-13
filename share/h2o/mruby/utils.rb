require 'rack'

module H2O
  module Utils
    def env_to_headers(env)
      hash = {}
      env.each {|k, v|
        next unless k[0, 5] == 'HTTP_'
        name = k[5..-1]
        name.gsub!('_', '-')
        name.downcase!
        hash[name] = v
      }
      Rack::Utils::HeaderHash.new(hash)
    end

    def env_key(header)
      "HTTP_#{header.upcase.gsub('-', '_')}"
    end

    def headers_to_env(headers)
      headers.map {|h, v| [env_key(h), v]}.to_h
    end
  end
end
