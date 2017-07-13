require 'cache/request'
require 'cache/response'
require 'cache/storage'

module H2O

  class Cache
    # https://tools.ietf.org/html/rfc7231#section-6.1
    CACHEABLE_STATUSES = [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501].map {|s| [s, true] }.to_h

    NOT_MODIFIED_UPDATE_HEADERS = ['Cache-Control', 'Date', 'Expires', 'ETag', 'Last-Modified'].map {|h| h.freeze }

    TRACE_HEADER = 'X-H2O-Cache-Trace'.freeze

    DEFAULT_OPTIONS = {
      :private_headers => ['Authorization'.freeze],
      :strip_headers => ['Set-Cookie'.freeze],
      :bypass_headers => [],
      :ignore_reload => false,
      :trace => false,
      :ttl => nil,
      :default_ttl => proc {|res|
        if CACHEABLE_STATUSES.include?(res.status)
          if res.last_modified
            ((res.now - res.last_modified) * 0.1).to_i
          else
            3600
          end
        else
          0
        end
      },
    }

    def initialize(app, storage, options={})
      @app = app
      @storage = storage
      @options = DEFAULT_OPTIONS.merge(options)
    end

    def call(env)
      req = Request.new(env, { :private_headers => @options[:private_headers] })
      return forward(req) unless req.get? || req.head?

      begin
        cached = @storage.lookup(req) {|reader|
          Response.new(req, reader.status, reader.res_headers, reader, {
            :ttl => @options[:ttl],
            :default_ttl => @options[:default_ttl],
            :time => reader.restime,
          })
        }

        if cached
          if need_revalidate?(cached, req)
            req.record(:revalidate)
            res = revalidate(cached, req)
            res.headers['Age'] = res.age.to_s if storable?(res, req)
          else
            req.record(:fresh)
            res = cached
            res.headers['Age'] = res.age.to_s
          end
        else
          req.record(:miss)
          res = fetch(req)
          res.headers['Age'] = res.age.to_s if storable?(res, req)
        end

        res.headers.delete('Server')
        res.empty_body! if req.head?
        res.not_modified! if not_modified?(res, req)
        res.headers[TRACE_HEADER] = req.recorded if @options[:trace]
      rescue => e
        # TODO log error
        res = forward(req)
      end

      res.to_a
    end

    def need_revalidate?(cached, req)
      return true if cached.no_cache?
      return true if cached.ttl <= 0
      unless @options[:ignore_reload]
        return true if req.no_cache?
        if req_max_age = req.cache_control.max_age
          return true if cached.age > req_max_age
        end
      end
      false
    end

    def not_modified?(res, req)
      inm = req.env['HTTP_IF_NONE_MATCH']
      ims = req.env['HTTP_IF_MODIFIED_SINCE']
      return false unless inm || ims
      if inm
        etags = inm.split(/\s*,\s*/)
        return false unless etags.include?(res.etag) || etags.include('*')
      end
      if ims
        return false unless res.headers['Last-Modified'] == ims
      end
      true
    end

    # https://tools.ietf.org/html/rfc7234#section-3
    def storable?(res, req)
      return false unless req.get? || req.head?
      return false if req.cache_control.no_store?
      return false if res.cache_control.no_store?
      return false if res.cache_control.private?
      return false if req.private? && !res.cache_control.public?

      return true if CACHEABLE_STATUSES.include?(res.status)
      return true if res.last_modified || res.etag
      return true if res.max_age
      return true if res.cache_control.public?

      return false
    end

    def revalidate(cached, req)
      env = req.env.dup
      env[REQUEST_METHOD] = GET if req.head?

      env['HTTP_IF_MODIFIED_SINCE'] = cached.last_modified.imf_fixdate if cached.last_modified
      env['HTTP_IF_NONE_MATCH'] = cached.etag if cached.etag

      res = forward(req, env)

      if res.status == 304
        req.record(:valid)
        NOT_MODIFIED_UPDATE_HEADERS.each {|name|
          next unless value = res.headers[name]
          cached.headers[name] = value
        }
        cached.time = res.time
        res.empty_body!
        res = cached
      else
        req.record(:invalid)
      end

      store(res, req) if storable?(res, req) # TODO store only headers if 304

      res
    end

    def store(res, req)
      @options[:strip_headers].each { |name| res.headers.delete(name) }

      nobypass_headers = res.headers
      unless @options[:bypass_headers].empty?
        res.headers = nobypass_headers.dup
        @options[:bypass_headers].each { |name| res.headers.delete(name) }
      end

      if req.head? || not_modified?(res, req)
        # body will be closed without being returned, so store it and doesn't rewind
        @storage.store(res, { :rewind => false })
      else
        # body will be returned, so rewind (default)
        @storage.store(res)
      end

      res.headers = nobypass_headers
      req.record(:store)
    end

    def fetch(req)
      env = req.env.dup
      env[REQUEST_METHOD] = GET if req.head?

      res = forward(req, env)
      store(res, req) if storable?(res, req)

      res
    end

    def forward(req, env = nil)
      env ||= req.env
      resp = @app.call(env)
      Response.new(req, *resp, { :default_ttl => @options[:default_ttl] })
    end

  end

end
