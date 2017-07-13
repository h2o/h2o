require File.expand_path('../lib/test_helper.rb', __FILE__)

require 'cache'
require 'utils'
require 'rack'
require 'tmpdir'
require 'timecop'
require 'time'

class CacheTest < MTest::Unit::TestCase
  include Rack
  include H2O::Utils;

  DEFAULT_ENV = {
    RACK_VERSION => 0,
    RACK_INPUT => [],
    RACK_ERRORS => [],
    RACK_MULTITHREAD => false,
    RACK_MULTIPROCESS => false,
    RACK_RUNONCE => false,
  }.freeze

  def assert_trace(expected, headers)
    assert_equal(expected, headers[H2O::Cache::TRACE_HEADER])
  end

  def create_cache(app, storage, options = {})
    options ||= {}
    options[:trace] = true unless options.key?(:trace)
    cache = H2O::Cache.new(app, storage, options)
    proc {|env|
        status, headers, body = cache.call(env)
        headers = Rack::Utils::HeaderHash.new(headers)
        headers['Date'] ||= Time.now.imf_fixdate
        [status, headers, body]
    }
  end

  def env_for(arg)
    env = DEFAULT_ENV.dup
    env[REQUEST_METHOD] = arg[:method] || GET
    env[SERVER_NAME] = arg[:host] || '127.0.0.1'
    env[SERVER_PORT] = arg[:port] || 80
    env[QUERY_STRING] = (arg[:params] || {}).map {|k, v| "#{k.to_s}=#{v.to_s}"}.join('&') # TODO tekitou
    env[PATH_INFO] = arg[:path] || '/'
    env[RACK_URL_SCHEME] = arg[:scheme] || 'http'
    env[HTTPS] = env[RACK_URL_SCHEME] == 'https' ? 'on' : 'off'
    env[SCRIPT_NAME] = arg[:script_name] || ''
    env[RACK_INPUT] = arg[:body] || []
    env['CONTENT_LENGTH'] ||= arg[:body].size if arg[:body].respond_to?(:size)

    env.merge!(headers_to_env(arg[:headers] || {}))

    env
  end

  def test_basic
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, {}, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)

      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('fresh', headers)

      status, headers, body = app.call(env_for({ :path => '/another' }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)
    }
  end

  def test_private_headers
    [nil, { :private_headers => [] }].each {|opts|
      Dir.mktmpdir {|tmpdir|
        app = create_cache(
          proc {|env|
            [200, {}, ["hello"]] },
          storage = H2O::Cache::Disk.new(tmpdir),
          opts,
        )
        status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Authorization' => 'hoge' } } ))
        assert_equal(200, status)
        assert_trace(opts ? 'miss, store' : 'miss', headers)
      }
    }
  end

  def test_strip_headers
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, { 'Set-Cookie' => 'hoge' }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_not_include(headers, 'Set-Cookie')
    }

    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, { 'Set-Cookie' => 'hoge' }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
        { :strip_headers => [] },
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_include(headers, 'Set-Cookie')
    }
  end

  def test_request_no_store
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, {}, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Cache-Control' => 'no-store' } }))
      assert_equal(200, status)
      assert_trace('miss', headers)
      assert_not_include(headers, 'Age')
    }
  end

  def test_request_no_cache
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, {}, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Cache-Control' => 'no-cache' } }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)

      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Cache-Control' => 'no-cache' } }))
      assert_equal(200, status)
      assert_trace('revalidate, invalid, store', headers)
    }
  end

  def test_ignore_reload
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, {}, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
        { :ignore_reload => true },
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)

      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Cache-Control' => 'no-cache' } }))
      assert_equal(200, status)
      assert_trace('fresh', headers)

      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'Cache-Control' => 'max-age=0' } }))
      assert_equal(200, status)
      assert_trace('fresh', headers)
    }
  end

  def test_response_no_store
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, { 'Cache-Control' => 'no-store' }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('miss', headers)
    }
  end

  def test_response_no_cache
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, { 'Cache-Control' => 'no-cache' }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)

      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('revalidate, invalid, store', headers)
    }
  end

  def test_expires
    now = Time.now
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          [200, { 'Expires' => (now + 2).imf_fixdate }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )

      Timecop.freeze(now) {
        status, headers, body = app.call(env_for({ :path => '/' }))
        assert_equal(200, status)
        assert_trace('miss, store', headers)
        assert_equal('0', headers['Age'])
      }
      Timecop.freeze(now + 1) {
        status, headers, body = app.call(env_for({ :path => '/' }))
        assert_equal(200, status)
        assert_trace('fresh', headers)
        assert_equal('1', headers['Age'])
      }
      Timecop.freeze(now + 2) {
        status, headers, body = app.call(env_for({ :path => '/' }))
        assert_equal(200, status)
        assert_trace('revalidate, invalid, store', headers)
        assert_equal('0', headers['Age'])
      }
      Timecop.freeze(now + 3) { # expires header is past
        status, headers, body = app.call(env_for({ :path => '/' }))
        assert_equal(200, status)
        assert_trace('revalidate, invalid, store', headers)
        assert_equal('0', headers['Age'])
      }
    }
  end

  def test_last_modified
    now = Time.now
    lm = now - 10;
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          headers = env_to_headers(env)
          ims = headers['If-Modified-Since']
          ims = Time.imf_fixdate(ims) if ims
          status = (ims && ims <= lm) ? 304 : 200
          [status, { 'Last-Modified' => lm.imf_fixdate }, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
      )
      status, headers, body = app.call(env_for({ :path => '/' }))
      assert_equal(200, status)
      assert_trace('miss, store', headers)
      assert_equal((now - 10).imf_fixdate, headers['Last-Modified'])

      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'If-Modified-Since' => headers['Last-Modified'] } }))
      assert_equal(304, status)
      assert_trace('fresh', headers)
      assert_equal((now - 10).imf_fixdate, headers['Last-Modified'])

      status, headers, body = app.call(env_for({ :path => '/', :headers => { 'If-Modified-Since' => headers['Last-Modified'], 'Cache-Control' => 'no-cache' } }))
      assert_equal(304, status)
      assert_trace('revalidate, valid, store', headers)
      assert_equal((now - 10).imf_fixdate, headers['Last-Modified'])
    }
  end

  def test_default_ttl
    now = Time.now
    Dir.mktmpdir {|tmpdir|
      app = create_cache(
        proc {|env|
          _, status = env['QUERY_STRING'].split('=')
          [status.to_i, {}, ["hello"]]
        },
        storage = H2O::Cache::Disk.new(tmpdir),
        { :default_ttl => proc {|res| res.status == 200 ? 3600 : 30 } },
      )

      Timecop.freeze(now) {
        status, headers, body = app.call(env_for({ :params => { :status => 200 } }))
        assert_equal(200, status)
        assert_trace('miss, store', headers)
        assert_equal('0', headers['Age'])
        status, headers, body = app.call(env_for({ :params => { :status => 404 } }))
        assert_equal(404, status)
        assert_trace('miss, store', headers)
        assert_equal('0', headers['Age'])
      }
      Timecop.freeze(now + 31) {
        status, headers, body = app.call(env_for({ :params => { :status => 200 } }))
        assert_equal(200, status)
        assert_trace('fresh', headers)
        assert_equal('31', headers['Age'])
        status, headers, body = app.call(env_for({ :params => { :status => 404 } }))
        assert_equal(404, status)
        assert_trace('revalidate, invalid, store', headers)
        assert_equal('0', headers['Age'])
      }
      Timecop.freeze(now + 3601) {
        status, headers, body = app.call(env_for({ :params => { :status => 200 } }))
        assert_equal(200, status)
        assert_trace('revalidate, invalid, store', headers)
        assert_equal('0', headers['Age'])
      }
    }
  end

end

MTest::Unit.new.run
